# Copyright (c) 2021 Linux Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# pylint: disable=E0401,E0611
# pyright: reportMissingImports=false,reportMissingModuleSource=false

import datetime
import logging
import os
import socket
import tempfile
from io import BytesIO
from time import sleep
from typing import Optional

import pandas as pd
import requests
import uvicorn
from fastapi import FastAPI, HTTPException, Response, status
from fastapi.responses import StreamingResponse
from psycopg2.extras import execute_values
from pydantic import BaseModel
from sqlalchemy import create_engine, sql, text
from sqlalchemy.exc import InterfaceError, OperationalError
from weasyprint import HTML


def make_clickable(url):
    anchor = url.split("/")[-1]
    return f'<a href="{url}">{anchor}</a>'


def is_blank(check_str):
    return not (check_str and check_str.strip())


# Init Globals
SERVICE_NAME = "ms-sbom-export"
DB_CONN_RETRY = 3

tags_metadata = [
    {
        "name": "health",
        "description": "health check end point",
    },
    {
        "name": "sbom",
        "description": "Retrieve Package Dependencies end point",
    },
]

# Init FastAPI
app = FastAPI(
    title=SERVICE_NAME,
    description="RestAPI endpoint for retrieving SBOM data to a component",
    version="10.0.0",
    license_info={
        "name": "Apache 2.0",
        "url": "https://www.apache.org/licenses/LICENSE-2.0.html",
    },
    servers=[{"url": "http://localhost:5004", "description": "Local Server"}],
    contact={
        "name": "DeployHub SBOM Export",
        "url": "https://github.com/DeployHubProject/DeployHub-Pro/issues",
        "email": "notify-support@deployhub.com",
    },
    openapi_tags=tags_metadata,
)

# Init db connection
db_host = os.getenv("DB_HOST", "localhost")
db_name = os.getenv("DB_NAME", "postgres")
db_user = os.getenv("DB_USER", "postgres")
db_pass = os.getenv("DB_PASS", "postgres")
db_port = os.getenv("DB_PORT", "5432")
validateuser_url = os.getenv("VALIDATEUSER_URL", "")

if len(validateuser_url) == 0:
    validateuser_host = os.getenv("MS_VALIDATE_USER_SERVICE_HOST", "127.0.0.1")
    host = socket.gethostbyaddr(validateuser_host)[0]
    validateuser_url = "http://" + host + ":" + str(os.getenv("MS_VALIDATE_USER_SERVICE_PORT", "80"))

deppkg_url = os.getenv("SCEC_DEPPKG_URL", "")

if len(deppkg_url) == 0:
    deppkg_host = os.getenv("SCEC_DEPPKG_SERVICE_HOST", "127.0.0.1")
    host = socket.gethostbyaddr(deppkg_host)[0]
    deppkg_url = "http://" + host + ":" + str(os.getenv("SCEC_DEPPKG_SERVICE_PORT", "80")) + "/msapi/package"

engine = create_engine("postgresql+psycopg2://" + db_user + ":" + db_pass + "@" + db_host + ":" + db_port + "/" + db_name, pool_pre_ping=True)


# health check endpoint
class StatusMsg(BaseModel):
    status: str = ""
    service_name: str = ""


@app.get("/health", tags=["health"])
async def health(response: Response) -> StatusMsg:
    """
    This health check end point used by Kubernetes
    """
    try:
        with engine.connect() as connection:
            conn = connection.connection
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            if cursor.rowcount > 0:
                return StatusMsg(status="UP", service_name=SERVICE_NAME)
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
            return StatusMsg(status="DOWN", service_name=SERVICE_NAME)

    except Exception as err:
        print(str(err))
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return StatusMsg(status="DOWN", service_name=SERVICE_NAME)


# end health check


@app.get("/msapi/sbom", tags=["sbom"])
# pylint: disable=C901
async def export_sbom(compid: Optional[str] = None, appid: Optional[str] = None, envid: Optional[str] = None):  # noqa: C901
    """
    This is the end point used to create PDF of the Application/Component SBOM
    """

    if compid is not None and (compid.startswith("cv") or compid.startswith("co")):
        compid = compid[2:]

    if appid is not None and (appid.startswith("av") or appid.startswith("ap")):
        appid = appid[2:]

    if envid is not None and (envid.startswith("en")):
        envid = envid[2:]

    try:
        # Retry logic for failed query
        no_of_retry = DB_CONN_RETRY
        attempt = 1
        while True:
            try:
                with engine.connect() as connection:
                    conn = connection.connection
                    cursor = conn.cursor()

                    sqlstmt = """CREATE TEMPORARY TABLE IF NOT EXISTS dm_sbom
                                (
                                    compid integer NOT NULL,
                                    packagename character varying(1024) NOT NULL,
                                    packageversion character varying(256) NOT NULL,
                                    name character varying(1024),
                                    url character varying(1024),
                                    summary character varying(8096),
                                    purl character varying(1024),
                                    pkgtype character varying(80)
                                )
                                """

                    cursor.execute(sqlstmt)

                    sqlstmt = """CREATE TEMPORARY TABLE IF NOT EXISTS dm_vulns
                                (
                                    packagename character varying(1024) NOT NULL,
                                    packageversion character varying(256) NOT NULL,
                                    id character varying(80) NOT NULL,
                                    purl character varying(1024),
                                    summary character varying(8096),
                                    risklevel character varying(256)
                                )
                                """

                    cursor.execute(sqlstmt)

                    complist = []
                    if appid is not None:
                        single_param = (str(appid),)

                        cursor.execute("select distinct compid from dm.dm_applicationcomponent a, dm.dm_component b where appid = %s and a.compid = b.id and b.status = 'N'", single_param)
                        rows = cursor.fetchall()

                        for row in rows:
                            complist.append(str(row[0]))

                    if envid is not None:
                        single_param = (str(envid),)

                        compsql = """
                                    WITH ranked_applist AS (
                                        SELECT
                                            id,
                                            name,
                                            created,
                                            parentid,
                                            predecessorid,
                                            environment_name,
                                            deploymentid,
                                            finishts,
                                            exitcode,
                                            domainid,
                                            predecessor_name,
                                            fullname,
                                            ROW_NUMBER() OVER (PARTITION BY parentid ORDER BY created DESC) AS rn
                                        FROM
                                            dm_applist
                                    )
                                    SELECT DISTINCT
                                        c.compid
                                    FROM
                                        ranked_applist a, dm.dm_deployment b, dm.dm_deploymentcomps c
                                    WHERE
                                    rn = 1
                                    and a.deploymentid > 0
                                    and b.envid = %s
                                    and a.deploymentid = b.deploymentid
                                    and a.deploymentid = c.deploymentid
                                    """
                        cursor.execute(
                            compsql,
                            single_param,
                        )
                        rows = cursor.fetchall()

                        for row in rows:
                            complist.append(str(row[0]))

                    if len(deppkg_url) > 0 and (compid is not None or appid is not None or envid is not None):
                        try:
                            url = deppkg_url

                            if compid is not None:
                                url = url + "?deptype=license&compid=" + str(compid)
                            else:
                                url = url + "?deptype=license&appid=" + ",".join(complist)

                            response = requests.get(url, timeout=120)
                            response.raise_for_status()
                            data = response.json()
                            rows = data.get("data", None)
                            if rows is not None:
                                insert_query = "INSERT INTO dm_sbom (compid, packagename, packageversion, name, url, summary, purl, pkgtype) VALUES %s"

                                # Extract values from the dictionaries into a list of tuples
                                values_list = [(row["key"], row["packagename"], row["packageversion"], row["name"], row["url"], row["summary"], "", row["pkgtype"]) for row in rows]

                                # Execute the insert query with execute_values
                                execute_values(cursor, insert_query, values_list)
                                print(data)
                        except requests.exceptions.HTTPError as err:
                            print(f"HTTP error occurred: {err}")
                        except requests.exceptions.RequestException as err:
                            print(f"An error occurred: {err}")

                        try:
                            url = deppkg_url

                            if compid is not None:
                                url = url + "?compid=" + str(compid)
                            else:
                                url = url + "?appid=" + ",".join(complist)

                            response = requests.get(url, timeout=120)
                            response.raise_for_status()
                            data = response.json()
                            rows = data.get("data", None)
                            if rows is not None:
                                insert_query = "INSERT INTO dm_vulns (packagename, packageversion, id, purl, summary, risklevel) VALUES %s"

                                # Extract values from the dictionaries into a list of tuples
                                vulns_list = [(row["packagename"], row["packageversion"], row["name"], row["url"], row["summary"], row["risklevel"]) for row in rows]

                                # Execute the insert query with execute_values
                                execute_values(cursor, insert_query, vulns_list)
                                print(data)
                        except requests.exceptions.HTTPError as err:
                            print(f"HTTP error occurred: {err}")
                        except requests.exceptions.RequestException as err:
                            print(f"An error occurred: {err}")

                    sqlstmt = ""
                    objid = compid
                    if compid is not None:
                        sqlstmt = """
                            SELECT '' as appname, 0 as deploymentid, b.packagename, b.packageversion, b.name, b.url, b.summary, c.name as compname, b.purl, b.pkgtype
                            FROM dm_sbom b, dm.dm_component c
                            where b.compid = :objid
                            and b.compid = c.id
                            UNION
                            SELECT '' as appname, 0 as deploymentid, b.packagename, b.packageversion, b.name, b.url, b.summary, c.name as compname, b.purl, b.pkgtype
                            FROM dm.dm_componentdeps b, dm.dm_component c
                            where b.compid = :objid and b.deptype = 'license'
                            and b.compid = c.id
                            """
                    elif appid is not None:
                        sqlstmt = """
                            select distinct '' as appname, 0 as deploymentid,  b.packagename, b.packageversion, b.name, b.url, b.summary, c.name as compname, b.purl, b.pkgtype
                            from dm.dm_applicationcomponent a, dm_sbom b, dm.dm_component c
                            where appid = :objid and a.compid = b.compid and c.id = b.compid
                            union
                            select distinct '' as appname, 0 as deploymentid, b.packagename, b.packageversion, b.name, b.url, b.summary, c.name as compname, b.purl, b.pkgtype
                            from dm.dm_applicationcomponent a, dm.dm_componentdeps b, dm.dm_component c
                            where appid = :objid and a.compid = b.compid and c.id = b.compid and b.deptype = 'license'
                            """
                        objid = appid
                    elif envid is not None:
                        sqlstmt = """
                                WITH ranked_applist AS (
                                    SELECT
                                        id,
                                        name,
                                        created,
                                        parentid,
                                        predecessorid,
                                        environment_name,
                                        deploymentid,
                                        finishts,
                                        exitcode,
                                        domainid,
                                        predecessor_name,
                                        fullname,
                                        ROW_NUMBER() OVER (PARTITION BY parentid ORDER BY created DESC) AS rn
                                    FROM
                                        dm_applist
                                )
                                SELECT DISTINCT
                                    a.name as appname,
                                    b.deploymentid,
                                    d.packagename,
                                    d.packageversion,
                                    d.name,
                                    d.url,
                                    d.summary,
                                    e.name as compname,
                                    d.purl,
                                    d.pkgtype
                                FROM
                                    ranked_applist a, dm.dm_deployment b, dm.dm_deploymentcomps c, dm.dm_componentdeps d, dm.dm_component e
                                WHERE
                                    rn = 1
                                and a.deploymentid > 0
                                and b.envid = :objid
                                and a.deploymentid = b.deploymentid
                                and a.deploymentid = c.deploymentid
                                and c.compid = d.compid
                                and c.compid = e.id
                                UNION
                                SELECT DISTINCT
                                    a.name as appname,
                                    b.deploymentid,
                                    d.packagename,
                                    d.packageversion,
                                    d.name,
                                    d.url,
                                    d.summary,
                                    e.name as compname,
                                    d.purl,
                                    d.pkgtype
                                FROM
                                    ranked_applist a, dm.dm_deployment b, dm.dm_deploymentcomps c, dm_sbom d, dm.dm_component e
                                WHERE
                                    rn = 1
                                and a.deploymentid > 0
                                and b.envid = :objid
                                and a.deploymentid = b.deploymentid
                                and a.deploymentid = c.deploymentid
                                and c.compid = d.compid
                                and c.compid = e.id
                            """
                        objid = envid

                    df_pkgs = pd.read_sql(sql.text(sqlstmt), connection, params={"objid": objid})

                    critical_table = ""
                    high_table = ""
                    medium_table = ""
                    low_table = ""
                    good_table = ""

                    if len(df_pkgs.index) > 0:
                        sqlstmt = """
                            select distinct id, packagename, packageversion, purl, summary as cve_summary, risklevel from dm_vulns
                            where (packagename || '@' || packageversion) = ANY(:pkglist) or purl = ANY(:purllist)
                            union
                            select distinct id, packagename, packageversion, purl, summary as cve_summary, risklevel from dm.dm_vulns
                            where (packagename || '@' || packageversion) = ANY(:pkglist) or purl = ANY(:purllist)
                            """

                        pkglist = (df_pkgs["packagename"] + "@" + df_pkgs["packageversion"]).to_list()
                        purllist = (df_pkgs.loc[df_pkgs["purl"].notnull()]["purl"]).to_list()

                        df_vulns = pd.read_sql(text(sqlstmt), connection, params={"pkglist": pkglist, "purllist": purllist})

                        df = df_pkgs.merge(df_vulns, how="left", on=["packagename", "packageversion"])
                        df.fillna("", inplace=True)
                        df.drop(["url", "summary", "purl_x", "pkgtype"], axis=1, inplace=True)

                        df["risklevel"] = pd.Categorical(df["risklevel"], ["Critical", "High", "Medium", "Low"])

                        if envid is not None:
                            df.sort_values(by=["risklevel", "packagename", "packageversion", "appname", "deploymentid"], inplace=True)
                        else:
                            df.sort_values(by=["risklevel", "packagename", "packageversion"], inplace=True)
                        df["risklevel"] = df["risklevel"].astype(str)
                        df["risklevel"] = df["risklevel"].replace("nan", "")

                        if envid is not None:
                            df.columns = ["Application", "Deployment", "Package", "Version", "License", "Component", "CVE", "Purl", "Description", "Risk Level"]
                            df = df.reindex(columns=["Application", "Deployment", "Package", "Version", "License", "CVE", "Purl", "Description", "Component", "Risk Level"])
                            df = df.drop("Purl", axis=1)
                        else:
                            df.columns = ["Application", "Deployment", "Package", "Version", "License", "Component", "CVE", "Purl", "Description", "Risk Level"]
                            df = df.reindex(columns=["Application", "Deployment", "Package", "Version", "License", "CVE", "Purl", "Description", "Component", "Risk Level"])
                            df = df.drop(["Application", "Deployment", "Purl"], axis=1)

                        df["CVE"] = df["CVE"].apply(lambda x: make_clickable("https://osv.dev/vulnerability/" + x) if len(x) > 0 else x)

                        critical_table = df.loc[df["Risk Level"] == "Critical"].drop("Risk Level", axis=1).to_html(classes=["critical-table"], index=False, escape=False, render_links=True)
                        high_table = df.loc[df["Risk Level"] == "High"].drop("Risk Level", axis=1).to_html(classes=["red-table"], index=False, escape=False, render_links=True)
                        medium_table = df.loc[df["Risk Level"] == "Medium"].drop("Risk Level", axis=1).to_html(classes=["orange-table"], index=False, escape=False, render_links=True)
                        low_table = df.loc[df["Risk Level"] == "Low"].drop("Risk Level", axis=1).to_html(classes=["gold-table"], index=False, escape=False, render_links=True)
                        good_table = df.loc[df["Risk Level"] == ""].drop("Risk Level", axis=1).to_html(classes=["blue-table"], index=False, escape=False, render_links=True)

                    params = (
                        str(),
                        str(),
                    )
                    objname = ""

                    if compid is not None:
                        single_param = (str(compid),)
                        cursor.execute("select name from dm.dm_component where id = %s", single_param)
                        rows = cursor.fetchall()

                        for row in rows:
                            objname = "Component<br>" + row[0]

                        sqlstmt = """
                            select distinct fulldomain(b.domainid, b.name), fulldomain(r.domainid, r.name) "repository", target "targetdirectory",
                                kind, buildid, buildurl, chart, builddate, dockerrepo, dockersha, gitcommit,
                                gitrepo, gittag, giturl, chartversion, chartnamespace, dockertag, chartrepo,
                                chartrepourl, c.id "serviceownerid", c.realname "serviceowner", c.email "serviceowneremail", c.phone "serviceownerphone",
                                slackchannel, discordchannel, hipchatchannel, pagerdutyurl, pagerdutybusinessurl
                                from dm.dm_componentitem a, dm.dm_component b, dm.dm_user c, dm.dm_repository r
                                where a.compid = b.id and b.ownerid = c.id and a.repositoryid = r.id and a.compid = %s
                            union
                                select fulldomain(b.domainid, b.name), null, target "targetdirectory",
                                kind, buildid, buildurl, chart, builddate, dockerrepo, dockersha, gitcommit,
                                gitrepo, gittag, giturl, chartversion, chartnamespace, dockertag, chartrepo,
                                chartrepourl, c.id "serviceownerid", c.realname "serviceowner", c.email "serviceowneremail", c.phone "serviceownerphone",
                                slackchannel, discordchannel, hipchatchannel, pagerdutyurl, pagerdutybusinessurl
                                from dm.dm_componentitem a, dm.dm_component b, dm.dm_user c
                                where a.compid = b.id and b.ownerid = c.id and a.repositoryid is null and a.compid = %s
                            """

                        params = (
                            str(compid),
                            str(compid),
                        )
                    elif appid is not None:
                        single_param = (str(appid),)
                        cursor.execute("select name from dm.dm_application where id = %s", single_param)
                        rows = cursor.fetchall()
                        for row in rows:
                            objname = "Application<br>" + row[0]

                        sqlstmt = """
                            select distinct fulldomain(b.domainid, b.name), fulldomain(r.domainid, r.name) "repository", target "targetdirectory",
                                kind, buildid, buildurl, chart, builddate, dockerrepo, dockersha, gitcommit,
                                gitrepo, gittag, giturl, chartversion, chartnamespace, dockertag, chartrepo,
                                chartrepourl, c.id "serviceownerid", c.realname "serviceowner", c.email "serviceowneremail", c.phone "serviceownerphone",
                                slackchannel, discordchannel, hipchatchannel, pagerdutyurl, pagerdutybusinessurl
                                from dm.dm_componentitem a, dm.dm_component b, dm.dm_user c, dm.dm_repository r
                                where a.compid = b.id and b.ownerid = c.id and a.repositoryid = r.id
                                and b.status = 'N'
                                and a.compid in (select compid from dm.dm_applicationcomponent where appid = %s)
                            union
                                select fulldomain(b.domainid, b.name), null, target "targetdirectory",
                                kind, buildid, buildurl, chart, builddate, dockerrepo, dockersha, gitcommit,
                                gitrepo, gittag, giturl, chartversion, chartnamespace, dockertag, chartrepo,
                                chartrepourl, c.id "serviceownerid", c.realname "serviceowner", c.email "serviceowneremail", c.phone "serviceownerphone",
                                slackchannel, discordchannel, hipchatchannel, pagerdutyurl, pagerdutybusinessurl
                                from dm.dm_componentitem a, dm.dm_component b, dm.dm_user c
                                where a.compid = b.id and b.ownerid = c.id and a.repositoryid is null
                                and b.status = 'N'
                                and a.compid in (select compid from dm.dm_applicationcomponent where appid = %s)
                            """

                        params = (
                            str(appid),
                            str(appid),
                        )
                    else:
                        single_param = (str(envid),)
                        cursor.execute("select name from dm.dm_environment where id = %s", single_param)
                        rows = cursor.fetchall()
                        for row in rows:
                            objname = "Environment<br>" + row[0]

                        sqlstmt = ""

                    comptable = ""
                    if len(sqlstmt) > 0:
                        cursor.execute(sqlstmt, params)
                        rows = cursor.fetchall()

                        for row in rows:
                            compname = row[0]
                            buildid = row[4]
                            buildurl = row[5]
                            chart = row[6]
                            builddate = row[7]
                            dockerrepo = row[8]
                            dockersha = row[9]
                            gitcommit = row[10]
                            gitrepo = row[11]
                            gittag = row[12]
                            giturl = row[13]
                            chartversion = row[14]
                            chartnamespace = row[15]
                            dockertag = row[16]
                            chartrepo = row[17]
                            chartrepourl = row[18]
                            serviceowner = row[20]
                            serviceowneremail = row[21]
                            serviceownerphone = row[22]
                            slackchannel = row[23]
                            discordchannel = row[24]
                            hipchatchannel = row[25]
                            pagerdutyurl = row[26]
                            pagerdutybusinessurl = row[27]

                            comp = f"""
                                <div style="width: 100%;"><h3>{compname}</h3>
                                    <div id="compsum" style="width: 50%; float: left;">
                                        <table id="compowner_summ" class="dev-table">
                                            <tr id="serviceowner_sumrow"><td class="summlabel">Service Owner:</td><td class="summval">{serviceowner}</td></tr>
                                            <tr id="serviceowneremail_sumrow"><td class="summlabel">Service Owner Email:</td><td class="summval">{serviceowneremail}</td></tr>
                                            <tr id="serviceownerphone_sumrow"><td class="summlabel">Service Owner Phone:</td><td class="summval">{serviceownerphone}</td></tr>
                                            <tr id="pagerdutybusinessserviceurl_sumrow"><td class="summlabel">PagerDuty Business Service Url:</td><td class="summval">{pagerdutybusinessurl}</td></tr>
                                            <tr id="pagerdutyserviceurl_sumrow"><td class="summlabel">PagerDuty Service Url:</td><td class="summval">{pagerdutyurl}</td></tr>
                                            <tr id="slackchannel_sumrow"><td class="summlabel">Slack Channel:</td><td class="summval">{slackchannel}</td></tr>
                                            <tr id="discordchannel_sumrow"><td class="summlabel">Discord Channel:</td><td class="summval">{discordchannel}</td></tr>
                                            <tr id="hipchatchannel_sumrow"><td class="summlabel">HipChat Channel:</td><td class="summval">{hipchatchannel}</td></tr>
                                            <tr id="gitcommit_sumrow"><td class="summlabel">Git Commit:</td><td class="summval">{gitcommit}</td></tr>
                                            <tr id="gitrepo_sumrow"><td class="summlabel">Git Repo:</td><td class="summval">{gitrepo}</td></tr>
                                            <tr id="gittag_sumrow"><td class="summlabel">Git Tag:</td><td class="summval">{gittag}</td></tr>
                                            <tr id="giturl_sumrow"><td class="summlabel">Git URL:</td><td class="summval">{giturl}</td></tr>
                                        </table>
                                    </div>

                                    <div id="compdetail" style="margin-left: 50%;">
                                        <table id="compitem" class="dev-table">
                                            <tr id="builddate_sumrow"><td class="summlabel">Build Date:</td><td class="summval">{builddate}</td></tr>
                                            <tr id="buildid_sumrow"><td class="summlabel">Build Id:</td><td class="summval">{buildid}</td></tr>
                                            <tr id="buildurl_sumrow"><td class="summlabel">Build URL:</td><td class="summval">{buildurl}</td></tr>
                                            <tr id="containerregistry_sumrow"><td class="summlabel">Container Registry:</td><td class="summval">{dockerrepo}</td></tr>
                                            <tr id="containerdigest_sumrow"><td class="summlabel">Container Digest:</td><td class="summval">{dockersha}</td></tr>
                                            <tr id="containertag_sumrow"><td class="summlabel">Container Tag:</td><td class="summval">{dockertag}</td></tr>
                                            <tr id="helmchart_sumrow"><td class="summlabel">Helm Chart:</td><td class="summval">{chart}</td></tr>
                                            <tr id="helmchartnamespace_sumrow"><td class="summlabel">Helm Chart Namespace:</td><td class="summval">{chartnamespace}</td></tr>
                                            <tr id="helmchartrepo_sumrow"><td class="summlabel">Helm Chart Repo:</td><td class="summval">{chartrepo}</td></tr>
                                            <tr id="helmchartrepourl_sumrow"><td class="summlabel">Helm Chart Repo Url:</td><td class="summval">{chartrepourl}</td></tr>
                                            <tr id="helmchartversion_sumrow"><td class="summlabel">Helm Chart Version:</td><td class="summval">{chartversion}</td></tr>
                                        </table>
                                    </div>
                                </div>
                                <br>
                            """
                            comptable = comptable + comp

                        cursor.close()
                        conn.commit()

                    rptdate = datetime.datetime.now().astimezone().strftime("%B %d, %Y at %I:%M %p %Z")
                    cover_url = os.getenv("COVER_URL", "https://www.deployhub.com/downloads/sbom-cover.svg")

                    cover_html = f"""
                        <html>
                        <head>
                            <title>SBOM Report</title>
                            <style>
                                body {{
                                    font-family: "Franklin Gothic Medium", "Arial Narrow", Arial, sans-serif;
                                }}

                                @page {{
                                    size: Letter landscape;
                                    margin: 0;
                                    paddng: 0;
                                    max-height: 8.5in;
                                    max-width: 11in;
                                }}

                                .coverpage {{
                                    margin: 0;
                                    padding: 0;
                                    height: 100%;
                                    width: 100%;
                                    position: absolute;
                                    top: 0;
                                    left: 0;
                                }}

                                .rptdate {{
                                    position: absolute;
                                    top: 700px;
                                    left: 72%;
                                    font-size: 1.3em;
                                    color: white;
                                }}

                                .objname {{
                                    position: absolute;
                                    top: 700px;
                                    font-size: 1.5em;
                                    left: 15px;
                                    color: white;
                                }}
                            </style>
                        </head>
                        <body>
                            <div>
                                <div class="coverpage">
                                    <img src="{cover_url}" />
                                    <div class="objname">{objname}</div>
                                    <p class="rptdate">{rptdate}</p>
                                </div>
                            </div>
                        </body>
                        </html>
                    """

                    html_string = f"""
                        <html>
                        <head>
                            <style>
                                @page {{
                                size: Letter landscape;
                                margin: .5in;
                                paddng: 0;
                                max-height: 8.5in;
                                max-width: 11in;
                                }}

                                table.blue-table {{
                                border: 1px solid #1c6ea4;
                                background-color: #eee;
                                width: 100%;
                                text-align: left;
                                border-collapse: collapse;
                                }}

                                table.blue-table td,
                                table.blue-table th {{
                                border: 1px solid #aaa;
                                padding: 3px 2px;
                                }}

                                table.blue-table th {{
                                text-align: center;
                                }}

                                table.blue-table tbody td {{
                                font-size: 12px;
                                }}

                                table.blue-table tr:nth-child(even) {{
                                background: #d0e4f5;
                                }}

                                table.blue-table thead {{
                                background: #1c6ea4;
                                }}

                                table.blue-table thead th {{
                                font-size: 12px;
                                font-weight: bold;
                                color: #fff;
                                border-left: 2px solid #d0e4f5;
                                }}

                                table.blue-table thead th:first-child {{
                                border-left: none;
                                }}

                                table.blue-table tfoot {{
                                font-size: 12px;
                                font-weight: bold;
                                color: #fff;
                                background: #d0e4f5;
                                border-top: 2px solid #444;
                                }}

                                table.blue-table tfoot td {{
                                font-size: 12px;
                                }}

                                table.blue-table tfoot .links {{
                                text-align: right;
                                }}

                                table.blue-table tfoot .links a {{
                                display: inline-block;
                                background: #1c6ea4;
                                color: #fff;
                                padding: 2px 8px;
                                border-radius: 5px;
                                }}

                                /* critical */
                                table.critical-table {{
                                border: 2px solid #f60a0a;
                                background-color: #eee7db;
                                width: 100%;
                                text-align: left;
                                border-collapse: collapse;
                                }}

                                table.critical-table tbody td {{
                                font-size: 12px;
                                }}

                                table.critical-table thead {{
                                background: #f60a0a;
                                border-bottom: 2px solid #444;
                                }}

                                table.critical-table thead th {{
                                font-size: 12px;
                                font-weight: bold;
                                color: #fff;
                                border-left: 2px solid #f60a0a;
                                }}

                                table.critical-table thead th:first-child {{
                                border-left: none;
                                }}

                                table.critical-table tfoot {{
                                font-size: 12px;
                                font-weight: bold;
                                color: #fff;
                                background: #f60a0a;
                                border-top: 2px solid #444;
                                }}

                                table.critical-table tfoot td {{
                                font-size: 12px;
                                }}

                                table.critical-table tfoot .links {{
                                text-align: right;
                                }}

                                table.critical-table tfoot .links a {{
                                display: inline-block;
                                background: #fff;
                                color: #f60a0a;
                                padding: 2px 8px;
                                border-radius: 5px;
                                }}

                                table.critical-table td,
                                table.critical-table th {{
                                border: 1px solid #aaa;
                                padding: 3px 2px;
                                }}

                                table.critical-table th {{
                                text-align: center;
                                }}

                                table.critical-table tr:nth-child(even) {{
                                background: #f5c8bf;
                                }}

                                /* red */
                                table.red-table {{
                                border: 2px solid #a40808;
                                background-color: #eee7db;
                                width: 100%;
                                text-align: left;
                                border-collapse: collapse;
                                }}

                                table.red-table tbody td {{
                                font-size: 12px;
                                }}

                                table.red-table thead {{
                                background: #a40808;
                                border-bottom: 2px solid #444;
                                }}

                                table.red-table thead th {{
                                font-size: 12px;
                                font-weight: bold;
                                color: #fff;
                                border-left: 2px solid #a40808;
                                }}

                                table.red-table thead th:first-child {{
                                border-left: none;
                                }}

                                table.red-table tfoot {{
                                font-size: 12px;
                                font-weight: bold;
                                color: #fff;
                                background: #a40808;
                                border-top: 2px solid #444;
                                }}

                                table.red-table tfoot td {{
                                font-size: 12px;
                                }}

                                table.red-table tfoot .links {{
                                text-align: right;
                                }}

                                table.red-table tfoot .links a {{
                                display: inline-block;
                                background: #fff;
                                color: #a40808;
                                padding: 2px 8px;
                                border-radius: 5px;
                                }}

                                table.red-table td,
                                table.red-table th {{
                                border: 1px solid #aaa;
                                padding: 3px 2px;
                                }}

                                table.red-table th {{
                                text-align: center;
                                }}

                                table.red-table tr:nth-child(even) {{
                                background: #f5c8bf;
                                }}

                                /* orange */
                                table.orange-table {{
                                border: 2px solid #ffa952;
                                background-color: #eee7db;
                                width: 100%;
                                text-align: left;
                                border-collapse: collapse;
                                }}

                                table.orange-table td,
                                table.orange-table th {{
                                border: 1px solid #aaa;
                                padding: 3px 2px;
                                }}

                                table.orange-table th {{
                                text-align: center;
                                }}

                                table.orange-table tbody td {{
                                font-size: 12px;
                                }}

                                table.orange-table tr:nth-child(even) {{
                                background: #f5c8bf;
                                }}

                                table.orange-table thead {{
                                background: #ffa952;
                                border-bottom: 2px solid #444;
                                }}

                                table.orange-table thead th {{
                                font-size: 12px;
                                font-weight: bold;
                                color: #fff;
                                border-left: 2px solid #ffa952;
                                }}

                                table.orange-table thead th:first-child {{
                                border-left: none;
                                }}

                                table.orange-table tfoot {{
                                font-size: 12px;
                                font-weight: bold;
                                color: #fff;
                                background: #ffa952;
                                border-top: 2px solid #444;
                                }}

                                table.orange-table tfoot td {{
                                font-size: 12px;
                                }}

                                table.orange-table tfoot .links {{
                                text-align: right;
                                }}

                                table.orange-table tfoot .links a {{
                                display: inline-block;
                                background: #fff;
                                color: #ffa952;
                                padding: 2px 8px;
                                border-radius: 5px;
                                }}

                                /* golden */
                                table.gold-table {{
                                border: 2px solid #ffe79a;
                                background-color: #eee7db;
                                width: 100%;
                                text-align: left;
                                border-collapse: collapse;
                                }}

                                table.gold-table td,
                                table.gold-table th {{
                                border: 1px solid #aaa;
                                padding: 3px 2px;
                                }}

                                table.gold-table th {{
                                text-align: center;
                                }}

                                table.gold-table tbody td {{
                                font-size: 12px;
                                }}

                                table.gold-table tr:nth-child(even) {{
                                background: #f5c8bf;
                                }}

                                table.gold-table thead {{
                                background: #ffe79a;
                                border-bottom: 2px solid #444;
                                }}

                                table.gold-table thead th {{
                                font-size: 12px;
                                font-weight: bold;
                                color: #fff;
                                border-left: 2px solid #ffe79a;
                                }}

                                table.gold-table thead th:first-child {{
                                border-left: none;
                                }}

                                table.gold-table tfoot {{
                                font-size: 12px;
                                font-weight: bold;
                                color: #fff;
                                background: #ffe79a;
                                border-top: 2px solid #444;
                                }}

                                table.gold-table tfoot td {{
                                font-size: 12px;
                                }}

                                table.gold-table tfoot .links {{
                                text-align: right;
                                }}

                                table.gold-table tfoot .links a {{
                                display: inline-block;
                                background: #fff;
                                color: #ffe79a;
                                padding: 2px 8px;
                                border-radius: 5px;
                                }}

                                body {{
                                font-family: "Franklin Gothic Medium", "Arial Narrow", Arial, sans-serif;
                                font-size: 12px;
                                }}

                                .dev-table {{
                                text-align: left;
                                }}

                                .summlabel {{
                                white-space: nowrap;
                                vertical-align: top;
                                padding: 2px 8px;
                                }}

                                .summval {{
                                word-break: break-all;
                                vertical-align: top;
                                padding: 2px 8px;
                                }}
                            </style>
                        </head>
                        <body>
                            <h3>Federated Component Evidence Details</h3>
                            {comptable}
                            <br>
                           <div id='critical'>
                                <h2>Critical Risk Packages</h2>
                                {critical_table}
                            </div>
                            <div id='high'>
                                <h2>High Risk Packages</h2>
                                {high_table}
                            </div>
                            <div id='medium'>
                                <h2>Medium Risk Packages</h2>
                                {medium_table}
                            </div>
                            <div id='low'>
                                <h2>Low Risk Packages</h2>
                                {low_table}
                            </div>
                            <div id='good'>
                                <h2>No Risk Packages</h2>
                                {good_table}
                            </div>
                        </body>
                        </html>
                        """

                    with tempfile.TemporaryDirectory() as tmp:
                        out_pdf = os.path.join(tmp, "sbom.pdf")
                        cover = os.path.join(tmp, "cover.html")
                        body = os.path.join(tmp, "body.html")

                        with open(cover, "w") as cover_file:
                            cover_file.write(cover_html)

                        with open(body, "w") as body_file:
                            body_file.write(html_string)

                        # Assemble cover page Document, should generate only 1 page within weasy_coverpage_doc.pages.
                        weasy_coverpage_html = HTML(filename=cover)
                        weasy_coverpage_doc = weasy_coverpage_html.render()

                        weasy_html = HTML(filename=body)
                        weasy_doc = weasy_html.render()

                        # Insert first (will be only) page from weasy_coverpage_doc into pages in weasy_doc.
                        weasy_doc.pages.insert(0, weasy_coverpage_doc.pages[0])
                        weasy_doc.write_pdf(out_pdf)

                        # Generate PDF using WeasyPrint
                        # HTML(string=html_string).write_pdf(out_pdf, stylesheets=["export.css"], presentational_hints=True, **options)
                        print("done!")

                        with open(out_pdf, "rb") as fh:
                            data = BytesIO(fh.read())
                            headers = {"Content-Disposition": 'inline; filename="sbom.pdf"', "content-type": "application/pdf"}
                            return StreamingResponse(data, media_type="application/pdf", headers=headers)

                    return {"error": "File not found!"}

            except (InterfaceError, OperationalError) as ex:
                if attempt < no_of_retry:
                    sleep_for = 0.2
                    logging.error("Database connection error: %s - sleeping for %d seconds and will retry (attempt #%d of %d)", ex, sleep_for, attempt, no_of_retry)
                    # 200ms of sleep time in cons. retry calls
                    sleep(sleep_for)
                    attempt += 1
                    continue
                else:
                    raise

    except HTTPException:
        raise
    except Exception as err:
        print(str(err))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(err)) from None


if __name__ == "__main__":
    uvicorn.run(app, port=5004)
