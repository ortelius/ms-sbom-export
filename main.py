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
from time import sleep
from typing import Optional

import pandas as pd
import requests
import uvicorn
from fastapi import FastAPI, HTTPException, Response, status
from fastapi.responses import HTMLResponse
from psycopg2.extras import execute_values
from pydantic import BaseModel
from sqlalchemy import create_engine, sql, text
from sqlalchemy.exc import InterfaceError, OperationalError

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(name)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")


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

        objname = ""
        comptable = ""
        critical_table = ""
        high_table = ""
        medium_table = ""
        low_table = ""
        good_table = ""

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
                    conn.commit()

                    complist = []
                    deploylist = []
                    if appid is not None:
                        single_param = (str(appid),)

                        cursor.execute("select distinct compid from dm.dm_applicationcomponent a, dm.dm_component b where appid = %s and a.compid = b.id and b.status = 'N'", single_param)
                        rows = cursor.fetchall()

                        for row in rows:
                            complist.append(str(row[0]))

                    if envid is not None:
                        single_param = (str(envid),)

                        compsql = """
                                select distinct b.compid, b.deploymentid from dm.dm_deploymentcomps b where b.deploymentid in (
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
                                        dm.dm_applist
                                )
                                SELECT DISTINCT
                                    b.deploymentid
                                FROM
                                    ranked_applist a
                                JOIN
                                    dm.dm_deployment b ON a.deploymentid = b.deploymentid
                                WHERE
                                    a.rn = 1
                                    AND a.deploymentid > 0
                                and b.envid = %s)
                                """

                        cursor.execute(
                            compsql,
                            single_param,
                        )
                        rows = cursor.fetchall()

                        for row in rows:
                            complist.append(str(row[0]))
                            deploylist.append(row[1])

                    complist = list(set(complist))
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
                                conn.commit()
                                logging.info("SBOM")
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
                                logging.info("CVE")
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
                                    dm.dm_application a, dm.dm_deployment b, dm.dm_applicationcomponent c, dm.dm_componentdeps d, dm.dm_component e
                                WHERE
                                    a.id = b.appid
                                AND a.id = c.appid
                                AND c.compid = e.id
                                AND c.compid = d.compid
                                AND b.deploymentid in :deploy
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
                                    dm.dm_application a, dm.dm_deployment b, dm.dm_applicationcomponent c, dm_sbom d, dm.dm_component e
                                WHERE
                                    a.id = b.appid
                                AND a.id = c.appid
                                AND c.compid = e.id
                                AND c.compid = d.compid
                                AND b.deploymentid in :deploy
                            """
                        objid = envid

                    df_pkgs = None
                    if envid is not None:

                        deploylist = list(set(deploylist))
                        df_pkgs = pd.read_sql(sql.text(sqlstmt), connection, params={"deploy": tuple(deploylist)})
                    else:
                        df_pkgs = pd.read_sql(sql.text(sqlstmt), connection, params={"objid": objid})

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
                                <div class="compsum" style="width: 100%;"><h3>{compname}</h3>
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
                                <br>
                            """
                            comptable = comptable + comp

                        cursor.close()
                        conn.commit()
                    break

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

        rptdate = datetime.datetime.now().astimezone().strftime("%B %d, %Y at %I:%M %p %Z")

        cover_html = f"""
            <html>
            <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>SBOM Report</title>
                <style>
                    body {{
                        font-family: "DejaVu Sans", "Liberation Sans", Arial, sans-serif;
                        font-size: 12px;
                    }}

                    .coverpage {{
                        margin: 0;
                        padding: 0;
                        width: 100%;
                        position: absolute;
                        top: 0;
                        left: 0;
                        height: 1610px;
                    }}

                    #coverimg {{
                      height: 1610px;
                      z-index: -1;
                    }}

                    .rptdate {{
                        position: relative;
                        bottom: 300px;
                        left: 72%;
                        font-size: 3em;
                        color: white;
                    }}

                    .objname {{
                        position: relative;
                        bottom: 180px;
                        font-size: 3em;
                        left: 15px;
                        color: white;
                    }}

                    table.blue-table {{
                        border: 1px solid #1c6ea4;
                        background-color: #eeeeee;
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

                    #details {{
                        position: absolute;
                        top: 1680;
                        margin-bottom: 20px;
                    }}

                    #savePdfBtn {{
                        position: fixed;
                        top: 10px;
                        right: 10px;
                        padding: 20px 40px;
                        background-color: #4CAF50;
                        color: white;
                        border: none;
                        border-radius: 5px;
                        cursor: pointer;
                        z-index:100;
                    }}

                    .saving-message {{
                        position: fixed;
                        top: 50%;
                        left: 50%;
                        transform: translate(-50%, -50%);
                        background-color: rgba(0, 0, 0, 0.8);
                        color: white;
                        padding: 40px;
                        border-radius: 5px;
                        z-index: 1000;
                        display: none;
                    }}
                </style>
                <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.3.1/jspdf.umd.min.js"></script>
                <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.8.2/jspdf.plugin.autotable.min.js"></script>
                <script src="https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js"></script>
            </head>
            <body>
                <script>
                const {{ jsPDF }} = window.jspdf;
                const doc = new jsPDF({{ orientation: 'landscape', unit: 'pt', format: 'letter' }});
                var isEnv = true;

                function addCompSumm() {{
                    // Select all divs containing tables with class 'compsum'
                    const divContainers = document.querySelectorAll('div.compsum');

                    // Variable to track vertical position
                    let startY = 20; // Initial startY position

                    // Iterate through each div.compsum
                    divContainers.forEach((divContainer, divIndex) => {{
                        isEnv = false;
                        // Get the title from h3 element inside div.compsum
                        const title = divContainer.querySelector('h3').innerText;

                        // Select all tables within the current div container
                        const tables = divContainer.querySelectorAll('table');

                        // Add title to the PDF
                        if (divIndex > 0) {{
                            startY = doc.autoTable.previous.finalY + 10; // Start below the previous section
                        }}
                        doc.setFontSize(12); // Set font size for title
                        doc.text(title, 20, startY + 10); // Adjusted coordinates for the title

                        // Function to convert each table to PDF
                        tables.forEach((table, index) => {{
                            // Convert table to PDF
                            const options = {{
                                html: table,
                                startY: index === 0 ? startY + 20 : doc.previousAutoTable.finalY + 10,
                                theme: 'plain', // or other theme options
                                styles: {{
                                    cellPadding: 1,
                                    fontSize: 10, // Font size for table content
                                    fontStyle: 'normal',
                                }}
                            }};

                            // Add the table to the PDF
                            doc.autoTable(options);
                        }});
                    }});
                }}

                function addTableToPDF(tableId, title) {{
                    const tableElement = document.querySelector('#' + tableId + ' > table');
                    if (!tableElement) return;

                    var colstyle =  {{
                            0: {{ cellWidth: 'auto' }},
                            1: {{ cellWidth: 'auto' }},
                            3: {{ cellWidth: 100 }}
                        }};

                    if (isEnv)
                        colstyle = {{
                            0: {{ cellWidth: 'auto' }},
                            1: {{ cellWidth: 'auto' }},
                            5: {{ cellWidth: 100 }}
                        }};

                    var headercolor = '#f60a0a';
                    var rowcolor = '#f5c8bf';
                    var altrowcolor = '#eee7db';

                    switch (tableId) {{
                        case 'high':
                            headercolor = '#a40808';
                            rowcolor = '#f5c8bf';
                            altrowcolor = '#eee7db';
                            break;
                        case 'medium':
                            headercolor = '#ffa952';
                            rowcolor = '#f5c8bf';
                            altrowcolor = '#eee7db';
                            break;
                        case 'low':
                            headercolor = '#ffe79a';
                            rowcolor = '#f5c8bf';
                            altrowcolor = '#eee7db';
                            break;
                        case 'good':
                            headercolor = '#1c6ea4';
                            rowcolor = '#d0e4f5';
                            altrowcolor = '#eeeeee';
                            break;
                        default:
                            break;
                    }}

                    // Calculate the startY position for the new table
                    var startY = doc.lastAutoTable ? doc.lastAutoTable.finalY + 40 : 40;

                    if (tableId == 'critical')
                        startY = doc.lastAutoTable ? doc.lastAutoTable.finalY + 40 : 80;

                    // Ensure startY is sufficient to accommodate the title
                    const titleHeight = 10; // Adjust as needed for your title font size and spacing
                    const availableSpace = doc.internal.pageSize.height - startY;
                    if (titleHeight > availableSpace) {{
                        doc.addPage();
                        startY = 40;
                    }}

                    // Add the title above the table
                    doc.text(title, 20, startY - 10);

                    // Convert table to PDF
                    doc.autoTable({{
                        html: tableElement,
                        startY: startY,
                        theme: 'grid',
                        margin: {{ top: 5, right: 5, bottom: 5, left: 5 }},
                        headStyles: {{
                            fillColor: headercolor,
                            cellWidth: 'wrap',
                            textColor: [255, 255, 255]
                        }},
                        columnStyles: colstyle,
                        styles: {{
                            fillColor: rowcolor,
                            textColor: [0, 0, 0],
                            fontSize: 10
                        }},
                        alternateRowStyles: {{
                            fillColor: altrowcolor,
                            textColor: [0, 0, 0]
                        }},
                        didParseCell: function (data) {{
                            if (data.cell.raw && data.cell.raw.tagName === 'TD') {{
                                // Get the HTML content of the <td> element
                                const cellHtml = data.cell.raw.innerHTML.trim();

                                // Check if the cell contains an <a> tag
                                const linkElement = data.cell.raw.querySelector('a');
                                if (linkElement) {{
                                    const linkText = linkElement.textContent.trim();
                                    const linkUrl = linkElement.href;
                                    data.cell.text = '';
                                    data.cell.linkText = linkText;  // Store the link text in the cell's data
                                    data.cell.linkUrl = linkUrl;  // Store the link URL in the cell's data

                                }} else {{
                                    // If the cell is plain text, use the text content
                                    data.cell.text = data.cell.raw.textContent.trim();
                                }}
                            }}
                        }},
                        didDrawCell: function (data) {{
                            if (data.cell.linkUrl) {{
                                const linkText = data.cell.linkText;
                                const linkUrl = data.cell.linkUrl;
                                const {{ doc, cell }} = data;

                                // Calculate the y-coordinate to align the text correctly within the cell
                                const x = cell.x + cell.padding('left');
                                const y = cell.y + cell.height / 2 + doc.getFontSize() / 2.8;

                                doc.setTextColor(0, 0, 255);  // Set the text color to blue (commonly used for links)
                                doc.textWithLink(String(linkText), x, y, {{ url: linkUrl }});
                                doc.setTextColor(0, 0, 0);  // Reset the text color to black
                            }}
                        }}
                    }});
                }}

                // Function to save the PDF
                async function saveAsPdf() {{
                    const element = document.getElementById('coverpage');
                    const canvas = await html2canvas(element);

                    const imgData = canvas.toDataURL('image/png');

                    const imgProps = doc.getImageProperties(imgData);
                    const pdfWidth = doc.internal.pageSize.width;
                    const pdfHeight = doc.internal.pageSize.height;

                    doc.addImage(imgData, 'PNG', 0, 0, pdfWidth, pdfHeight);
                    doc.addPage();
                    addCompSumm();
                    doc.text('Federated Component Evidence Details', 15, 30);

                    addTableToPDF('critical', 'Critical Risk Packages');
                    addTableToPDF('high', 'High Risk Packages');
                    addTableToPDF('medium', 'Medium Risk Packages');
                    addTableToPDF('low', 'Low Risk Packages');
                    addTableToPDF('good', 'No Risk Packages');
                    doc.save('sbom.pdf');
                }}

                </script>

                <button id="savePdfBtn" onclick="saveAsPdf()">Save as PDF</button>
                <div class="saving-message" id="savingMessage">Saving to PDF...</div>
                <div id="report">
                <div>
                    <div id="coverpage" class="coverpage">
                        <div id="coverimg">
                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 2089.66 1610">
                            <g style="isolation: isolate;">
                                <g id="Design">
                                <g>
                                    <rect width="2089.66" height="1610" style="fill: #fff;"/>
                                    <polygon points="2089.66 0 2089.66 318.73 1662.11 318.73 1510.02 0 2089.66 0" style="fill: #ffa103;"/>
                                    <polygon points="1029.04 1610 0 1610 0 768.61 627.51 768.61 1029.04 1610" style="fill: #ffa103;"/>
                                    <polygon points="1042.38 1610 963.83 1610 550.37 768.61 628.74 768.61 1042.38 1610" style="fill: #4c4c4c;"/>
                                    <g>
                                    <path d="m1658.48,675.13c-5.52-1.74-9.95-4.01-13.29-6.8l5.87-14.18c3.2,2.56,7.01,4.61,11.42,6.16,4.41,1.55,8.82,2.33,13.24,2.33,4.91,0,8.54-.79,10.89-2.38,2.35-1.59,3.52-3.7,3.52-6.34,0-1.94-.69-3.55-2.08-4.83s-3.17-2.31-5.34-3.08c-2.17-.77-5.11-1.63-8.81-2.56-5.7-1.47-10.36-2.94-13.99-4.42-3.63-1.47-6.74-3.84-9.34-7.09-2.6-3.26-3.9-7.6-3.9-13.02,0-4.73,1.17-9.01,3.52-12.85,2.35-3.84,5.89-6.88,10.62-9.13,4.73-2.25,10.52-3.37,17.35-3.37,4.77,0,9.43.62,13.99,1.86,4.55,1.24,8.54,3.02,11.96,5.35l-5.34,14.3c-6.9-4.26-13.81-6.4-20.71-6.4-4.84,0-8.42.85-10.73,2.56-2.31,1.71-3.47,3.95-3.47,6.74s1.33,4.87,4,6.22c2.67,1.36,6.74,2.69,12.22,4.01,5.69,1.47,10.36,2.95,13.99,4.42,3.63,1.47,6.74,3.8,9.34,6.98,2.6,3.18,3.9,7.48,3.9,12.91,0,4.65-1.19,8.89-3.58,12.73-2.39,3.84-5.96,6.88-10.73,9.13-4.77,2.25-10.57,3.37-17.4,3.37-5.91,0-11.62-.87-17.13-2.62Z" style="fill: #414042;"/>
                                    <path d="m1784.08,641.41c2.42,3.45,3.63,7.69,3.63,12.73,0,7.13-2.55,12.62-7.63,16.45-5.09,3.84-12.51,5.76-22.26,5.76h-38.65v-81.39h36.51c9.11,0,16.1,1.9,20.98,5.7,4.87,3.8,7.31,8.95,7.31,15.46,0,3.95-.87,7.48-2.62,10.58-1.75,3.1-4.18,5.54-7.31,7.32,4.27,1.47,7.61,3.94,10.04,7.38Zm-47.72-32.26v19.18h17.19c4.27,0,7.51-.81,9.71-2.44,2.21-1.63,3.31-4.03,3.31-7.21s-1.1-5.56-3.31-7.15c-2.21-1.59-5.44-2.38-9.71-2.38h-17.19Zm30.48,50.58c2.31-1.63,3.47-4.15,3.47-7.56,0-6.74-4.59-10.12-13.77-10.12h-20.18v20.11h20.18c4.55,0,7.99-.81,10.3-2.44Z" style="fill: #414042;"/>
                                    <path d="m1816.05,672.28c-6.23-3.64-11.1-8.66-14.63-15.06-3.52-6.39-5.29-13.58-5.29-21.57s1.76-15.17,5.29-21.57c3.52-6.4,8.4-11.41,14.63-15.06,6.23-3.64,13.22-5.46,20.98-5.46s14.73,1.82,20.92,5.46c6.19,3.64,11.07,8.66,14.63,15.06,3.56,6.39,5.34,13.58,5.34,21.57s-1.78,15.17-5.34,21.57c-3.56,6.39-8.43,11.41-14.63,15.06-6.19,3.64-13.17,5.46-20.92,5.46s-14.75-1.82-20.98-5.46Zm32.93-13.89c3.56-2.21,6.35-5.29,8.38-9.24s3.04-8.45,3.04-13.49-1.01-9.53-3.04-13.49c-2.03-3.95-4.82-7.03-8.38-9.24-3.56-2.21-7.54-3.31-11.96-3.31s-8.4,1.1-11.96,3.31c-3.56,2.21-6.35,5.29-8.38,9.24-2.03,3.95-3.04,8.45-3.04,13.49s1.01,9.53,3.04,13.49c2.03,3.95,4.82,7.03,8.38,9.24,3.56,2.21,7.54,3.31,11.96,3.31s8.4-1.1,11.96-3.31Z" style="fill: #414042;"/>
                                    <path d="m1958.95,676.35l-.11-48.83-21.99,40.23h-7.79l-21.89-39.18v47.79h-16.23v-81.39h14.3l27.97,50.58,27.54-50.58h14.2l.21,81.39h-16.23Z" style="fill: #414042;"/>
                                    <path d="m1417.61,729.89l-30.7,102.21h-23.33l-20.65-69.21-21.32,69.21h-23.19l-30.84-102.21h22.52l21.18,71.84,22.12-71.84h20.11l21.45,72.42,21.85-72.42h20.78Z" style="fill: #414042;"/>
                                    <path d="m1447.7,826.98c-7.82-4.57-13.94-10.88-18.37-18.91-4.42-8.03-6.64-17.06-6.64-27.08s2.21-19.05,6.64-27.08c4.42-8.03,10.54-14.33,18.37-18.91,7.82-4.57,16.6-6.86,26.34-6.86s18.5,2.29,26.28,6.86c7.78,4.58,13.9,10.88,18.37,18.91,4.47,8.03,6.7,17.06,6.7,27.08s-2.23,19.05-6.7,27.08c-4.47,8.03-10.59,14.33-18.37,18.91-7.78,4.58-16.54,6.86-26.28,6.86s-18.52-2.29-26.34-6.86Zm41.36-17.45c4.47-2.77,7.98-6.64,10.52-11.61,2.55-4.96,3.82-10.61,3.82-16.94s-1.27-11.97-3.82-16.94-6.06-8.83-10.52-11.61c-4.47-2.77-9.47-4.16-15.02-4.16s-10.55,1.39-15.02,4.16c-4.47,2.77-7.98,6.64-10.52,11.61-2.55,4.96-3.82,10.61-3.82,16.94s1.27,11.97,3.82,16.94c2.55,4.96,6.05,8.83,10.52,11.61,4.47,2.77,9.47,4.16,15.02,4.16s10.55-1.39,15.02-4.16Z" style="fill: #414042;"/>
                                    <path d="m1601.55,832.09l-18.1-28.47h-19.98v28.47h-21.72v-102.21h40.62c8.31,0,15.53,1.51,21.65,4.53,6.12,3.02,10.84,7.3,14.14,12.85,3.31,5.55,4.96,12.12,4.96,19.71s-1.68,14.14-5.03,19.64c-3.35,5.5-8.11,9.71-14.28,12.63l21.05,32.85h-23.33Zm-5.5-78.33c-3.4-3.07-8.36-4.6-14.88-4.6h-17.7v35.63h17.7c6.52,0,11.48-1.56,14.88-4.67,3.4-3.11,5.09-7.49,5.09-13.14s-1.7-10.15-5.09-13.21Z" style="fill: #414042;"/>
                                    <path d="m1674.48,791.94l-12.6,14.31v25.84h-21.58v-102.21h21.58v47.75l41.56-47.75h24.13l-38.88,45.55,41.16,56.65h-25.34l-30.03-40.15Z" style="fill: #414042;"/>
                                    <path d="m1739.5,729.89h21.72v102.21h-21.72v-102.21Z" style="fill: #414042;"/>
                                    <path d="m1869.54,729.89v102.21h-17.83l-46.79-62.05v62.05h-21.45v-102.21h17.96l46.66,62.05v-62.05h21.45Z" style="fill: #414042;"/>
                                    <path d="m1955.21,779.38h19.84v41.47c-5.09,4.19-10.99,7.4-17.7,9.64-6.7,2.24-13.45,3.36-20.24,3.36-9.74,0-18.5-2.26-26.28-6.79-7.78-4.53-13.88-10.81-18.3-18.84-4.42-8.03-6.64-17.11-6.64-27.23s2.21-19.2,6.64-27.23c4.42-8.03,10.57-14.31,18.43-18.84,7.86-4.53,16.71-6.79,26.55-6.79,8.22,0,15.69,1.51,22.39,4.53,6.7,3.02,12.33,7.4,16.89,13.14l-13.94,14.02c-6.7-7.69-14.79-11.53-24.27-11.53-5.99,0-11.31,1.36-15.95,4.09-4.65,2.73-8.27,6.57-10.86,11.53-2.59,4.96-3.89,10.66-3.89,17.08s1.29,11.97,3.89,16.94c2.59,4.96,6.19,8.83,10.79,11.61,4.6,2.77,9.85,4.16,15.75,4.16,6.25,0,11.89-1.46,16.89-4.38v-29.93Z" style="fill: #414042;"/>
                                    <path d="m1475.12,990.27l-18.1-28.47h-19.98v28.47h-21.72v-102.21h40.62c8.31,0,15.53,1.51,21.65,4.53,6.12,3.02,10.84,7.3,14.14,12.85,3.31,5.55,4.96,12.12,4.96,19.71s-1.68,14.14-5.03,19.64c-3.35,5.5-8.11,9.71-14.28,12.63l21.05,32.85h-23.33Zm-5.5-78.33c-3.4-3.07-8.36-4.6-14.88-4.6h-17.7v35.63h17.7c6.52,0,11.48-1.56,14.88-4.67,3.4-3.11,5.09-7.49,5.09-13.14s-1.7-10.15-5.09-13.21Z" style="fill: #ffa103;"/>
                                    <path d="m1586.53,971.29v18.98h-72.66v-102.21h70.92v18.98h-49.34v22.19h43.57v18.4h-43.57v23.65h51.08Z" style="fill: #ffa103;"/>
                                    <path d="m1666.1,892.59c6.12,3.02,10.84,7.3,14.14,12.85,3.31,5.55,4.96,12.12,4.96,19.71s-1.66,14.04-4.96,19.64c-3.31,5.6-8.02,9.88-14.14,12.85-6.12,2.97-13.34,4.45-21.65,4.45h-18.9v28.18h-21.72v-102.21h40.62c8.31,0,15.53,1.51,21.65,4.53Zm-7.98,45.63c3.4-3.07,5.09-7.42,5.09-13.07s-1.7-10.15-5.09-13.21c-3.4-3.07-8.36-4.6-14.88-4.6h-17.7v35.48h17.7c6.52,0,11.48-1.53,14.88-4.6Z" style="fill: #ffa103;"/>
                                    <path d="m1721.06,985.16c-7.82-4.57-13.94-10.88-18.37-18.91-4.42-8.03-6.64-17.06-6.64-27.08s2.21-19.05,6.64-27.08c4.42-8.03,10.54-14.33,18.37-18.91,7.82-4.57,16.6-6.86,26.34-6.86s18.5,2.29,26.28,6.86c7.78,4.58,13.9,10.88,18.37,18.91,4.47,8.03,6.7,17.06,6.7,27.08s-2.23,19.05-6.7,27.08c-4.47,8.03-10.59,14.33-18.37,18.91-7.78,4.58-16.54,6.86-26.28,6.86s-18.52-2.29-26.34-6.86Zm41.36-17.45c4.47-2.77,7.98-6.64,10.52-11.61,2.55-4.96,3.82-10.61,3.82-16.94s-1.27-11.97-3.82-16.94-6.06-8.83-10.52-11.61c-4.47-2.77-9.47-4.16-15.02-4.16s-10.55,1.39-15.02,4.16c-4.47,2.77-7.98,6.64-10.52,11.61-2.55,4.96-3.82,10.61-3.82,16.94s1.27,11.97,3.82,16.94c2.55,4.96,6.05,8.83,10.52,11.61,4.47,2.77,9.47,4.16,15.02,4.16s10.55-1.39,15.02-4.16Z" style="fill: #ffa103;"/>
                                    <path d="m1874.9,990.27l-18.1-28.47h-19.98v28.47h-21.72v-102.21h40.62c8.31,0,15.53,1.51,21.65,4.53,6.12,3.02,10.84,7.3,14.14,12.85,3.31,5.55,4.96,12.12,4.96,19.71s-1.68,14.14-5.03,19.64c-3.35,5.5-8.11,9.71-14.28,12.63l21.05,32.85h-23.33Zm-5.5-78.33c-3.4-3.07-8.36-4.6-14.88-4.6h-17.7v35.63h17.7c6.52,0,11.48-1.56,14.88-4.67,3.4-3.11,5.09-7.49,5.09-13.14s-1.7-10.15-5.09-13.21Z" style="fill: #ffa103;"/>
                                    <path d="m1931.75,907.34h-30.03v-19.27h81.78v19.27h-30.03v82.93h-21.72v-82.93Z" style="fill: #ffa103;"/>
                                    </g>
                                    <polygon points="2089.66 0 2089.66 291.72 1616.8 291.72 1477.6 0 2089.66 0" style="fill: #4c4c4c;"/>
                                    <g>
                                    <polygon points="2089.66 1409.63 2089.66 1487.12 1489.89 1486.96 1452.89 1409.47 2089.66 1409.63" style="fill: #4c4c4c;"/>
                                    <polygon points="1481.15 1486.99 1451.23 1424.34 1459.99 1424.34 1489.88 1486.96 1481.15 1486.99" style="fill: #ffa103;"/>
                                    </g>
                                    <polygon points="994.31 0 627.51 768.61 0 768.61 0 0 994.31 0" style="fill: #bcbec0;"/>
                                    <polygon points="994.31 0 627.14 768.61 386.69 768.61 753.48 0 994.31 0" style="fill: #4c4c4c; mix-blend-mode: multiply; opacity: .5;"/>
                                </g>
                                <g>
                                    <path d="m1792.02,77.51c-5.17,4.84-9.93,12.71-13.55,22.38-3.31,8.85-5.67,22.88-4.14,24.67.68.79,1.48.29,5.01-3.14,4.41-4.28,7.97-7.06,12.96-10.11,5.66-3.47,9.48-5.32,15.39-7.47,4.86-1.77,5.17-2.09,4.6-4.78-1.3-6.12-6.87-16.04-11.65-20.76-2.42-2.38-3.62-3.14-4.99-3.14-1.05,0-1.28.15-3.63,2.35m74.58-1.19c-5.11,3.54-9.33,9.99-13.03,19.89-1.18,3.17-1.41,4.28-1.06,5.07.38.85,1.06,1.21,5.1,2.67,10.27,3.72,19.43,9.38,27.58,17.02,4.27,4,5.01,4.45,5.63,3.38.97-1.67-.54-12.19-2.9-20.19-3.31-11.22-9.64-22.22-15.92-27.67-2.07-1.79-3.01-1.82-5.39-.17m-69.06,48.72c-8.32,1.59-14.54,7.04-17.11,14.98-.98,3.03-1.22,7.9-.54,11,1.02,4.64,2.96,7.94,6.61,11.27,2.56,2.33,4.9,3.68,7.93,4.57,9.43,2.75,19.83-1.9,24.35-10.9,1.67-3.32,2.12-5.34,2.12-9.52,0-3.26-.08-3.93-.74-5.94-1.48-4.54-4.41-8.68-8.02-11.38-2.15-1.6-6.11-3.39-8.53-3.86-1.81-.35-4.82-.45-6.06-.21m64.76,14.33c-1.47.7-2.81,1.89-3.53,3.13-.81,1.41-.81,3.92,0,5.34.7,1.23,2.53,2.81,3.82,3.3,3.75,1.44,8.61-1.45,9.12-5.43.59-4.61-5.06-8.42-9.41-6.35m-63.24.47c-4.93.8-6.37,6.1-2.58,9.49,3.17,2.84,8.76.81,9.62-3.48.38-1.91-1.02-4.48-2.93-5.39-1.11-.53-2.95-.8-4.1-.61m27.39,32.47c-5,.6-8.42,2.41-9.93,5.24-2.78,5.22,2.23,14.63,9.81,18.46,3.08,1.56,2.88.77,3.05,12.05.13,9.08.18,9.84.69,10.78.61,1.12,1.76,1.78,3.63,2.05,1.04.15,1.24.09,1.98-.58,1.53-1.41,1.89-3.93,2.14-15.11l.18-8.06,2.37-1.19c3.16-1.59,7.18-5.22,8.62-7.79,3.32-5.9,2.11-11.68-2.94-13.96-3.55-1.6-13.78-2.58-19.6-1.88" style="fill: #5a5c5c; fill-rule: evenodd;"/>
                                    <path d="m1824,24.41c-.3.11-1.61.28-2.89.37-3.09.23-10.01,1.28-14.42,2.2-30.3,6.33-57.16,24.38-73.54,49.44-9,13.77-14.49,28.99-16.32,45.24-.57,5.03-.57,16.74,0,22,2.25,21,10.99,40.59,25.7,57.6,3.6,4.17,12.53,12.43,17.15,15.88,3.39,2.53,3.45,2.56,3.53,1.85.05-.4-.19-1.39-.52-2.21-2.5-6.2-4.86-15.69-5.82-23.3-.78-6.28-.31-20.04,1.02-29.93,1.22-9.04,4.34-21.51,6.64-26.6.66-1.46.72-1.94.94-7.64.37-9.77.8-13.55,2.34-20.57,3.47-15.78,10.08-29.08,18.16-36.51,2.7-2.49,3.35-2.94,5.74-4.03,3.21-1.46,4.01-1.46,7.2-.07,8.78,3.84,15.04,11.66,20.02,24.99,1.12,3,1.61,3.98,2.13,4.3.64.39,6.42.64,21.19.92,2.19.04,2.52-.37,4.37-5.62,2.77-7.83,6.85-14.45,11.94-19.39,3.99-3.86,7.84-5.83,11.47-5.86,2.16-.01,3.17.31,5.58,1.78,9.61,5.85,18.57,22.04,22.23,40.15,1.38,6.81,1.6,9.12,1.8,18.9l.19,9.38.84,2.41c1.31,3.73,2.18,8.32,3,15.73.59,5.34.84,24.21.41,30.77-.53,8.08-1.39,14.45-2.55,19.07-.71,2.8-3.44,10.01-5.09,13.44-1.16,2.41-1.83,4.95-1.3,4.94.13,0,1.94-1.12,4.01-2.47,18.32-12,32.37-28.26,40.92-47.32,4.57-10.19,7.5-21.41,8.53-32.63.14-1.54.26-1.98.4-1.52.11.35.2-3.13.19-7.74,0-4.6-.09-7.97-.2-7.48-.16.75-.22.57-.4-1.14-1.5-14.5-5.22-26.93-11.69-39.06-14.31-26.79-39.28-46.6-70.18-55.66-5.72-1.68-14.12-3.31-20.28-3.94-2.18-.22-4.5-.51-5.14-.65-1.4-.29-16.49-.3-17.29-.01m-31.83,52.65c-.67.63-1.15,1.14-1.08,1.14s.69-.51,1.35-1.14,1.15-1.14,1.08-1.14-.69.51-1.35,1.14m-75.66,55.55c0,4.6.04,6.52.08,4.26.05-2.26.05-6.02,0-8.37-.05-2.35-.08-.5-.08,4.11m62.78,13.95c0,.7.06.95.12.57.06-.39.06-.96,0-1.27-.07-.31-.12,0-.12.7" style="fill: #f8951a; fill-rule: evenodd;"/>
                                    <path d="m1791.62,68.22c-2.28,1.05-3.01,1.57-5.67,4.01-8.08,7.43-14.69,20.73-18.16,36.51-1.56,7.08-2.32,14.23-2.36,22.09-.02,3.57-.11,4.03-1.76,8.37-2.78,7.33-5.31,18.88-6.36,29.04-1.48,14.23-1.09,25.18,1.26,35.15.89,3.76,3.16,11.22,3.86,12.66.41.84.63,1.79.64,2.83l.02,1.56,1.44.85c.79.47,2.19,1.68,3.11,2.69l1.67,1.84h123.44l1.12-.75c1.04-.69,1.13-.85,1.21-2.09.06-.92.48-2.15,1.32-3.88,1.64-3.37,4.39-10.6,5.1-13.44,1.17-4.62,2.02-10.99,2.55-19.07.43-6.55.18-25.43-.41-30.77-.82-7.4-1.69-12-3-15.73l-.84-2.41-.19-9.38c-.2-9.78-.42-12.08-1.8-18.9-3.66-18.11-12.62-34.3-22.23-40.15-2.42-1.47-3.42-1.79-5.58-1.78-8.26.06-18.34,10.93-23.41,25.24-1.86,5.25-2.18,5.66-4.37,5.62-14.77-.28-20.55-.53-21.19-.92-.53-.32-1.01-1.3-2.13-4.3-4.98-13.35-11.24-21.15-20.03-25-3.15-1.38-4.1-1.37-7.26.09m2.42,7.43c-2.76,1.61-7.36,7.44-10.75,13.6-4.42,8.05-6.98,15.51-8.75,25.48-1.07,6.04-1.01,9.83.17,10.24.62.22,1.92-.66,3.4-2.31,1.73-1.93,6.03-5.72,8.82-7.77,5.8-4.27,13.22-8.23,20.25-10.83,1.97-.73,3.99-1.6,4.48-1.94,1.12-.77,1.16-1.6.25-4.65-2.05-6.83-7.31-15.62-11.93-19.93-2.74-2.56-4.08-2.99-5.95-1.89m74.67-.47c-1.98.51-5.9,3.99-8.27,7.35-1.71,2.43-3.66,5.91-4.92,8.8-1.27,2.91-2.97,7.58-3.16,8.67-.32,1.82.11,2.12,6.09,4.3,4.37,1.6,8.73,3.74,13.54,6.67,5.36,3.26,8.86,5.92,13.35,10.13,4.11,3.85,4.88,4.31,5.48,3.27.72-1.23.49-4.85-.71-11.17-2.51-13.23-7.28-24.2-14.17-32.59-2.15-2.61-4.77-5.07-5.78-5.4-.38-.13-1.03-.14-1.45-.04m-72.46,50.07c-3.78.88-7.31,2.86-10.32,5.78-4.34,4.21-6.51,9.38-6.51,15.53,0,6.48,2.47,11.83,7.49,16.17,4.72,4.09,10.63,5.74,16.56,4.65,9.77-1.81,16.94-9.86,17.53-19.67.39-6.52-2.04-12.38-7.05-17.02-2.63-2.43-5.23-3.98-8.34-4.97-2.54-.81-6.98-1.03-9.37-.47m66.01,14.09c-1.31.6-2.98,2.05-3.63,3.16-.64,1.09-.62,4.03.04,5.24,1.22,2.26,3.64,3.76,6.06,3.76,1.84,0,3.16-.49,4.64-1.72,3.85-3.2,2.93-8.49-1.84-10.49-1.51-.63-3.83-.61-5.27.04m-64.72.96c-2.04.89-3.17,2.61-3.16,4.79,0,1.59.74,3.02,2.14,4.18,2.03,1.68,4.66,1.78,6.96.26,3.5-2.32,3.48-6.71-.04-8.86-1.52-.93-4.24-1.1-5.9-.38m28.39,32.03c-8.85,1.19-12.33,6.5-9.05,13.79,1.71,3.8,5.61,7.95,9.31,9.91,3.23,1.71,3.02.89,3.18,12.24.15,10.57.18,10.77,1.65,11.74.38.25,1.26.6,1.96.76,2.32.56,3.39-.28,4.1-3.22.43-1.77.8-8.43.81-14.75,0-3.98.1-5.45.35-5.65.19-.15,1.45-.87,2.8-1.6,4.16-2.25,7.14-5.38,8.92-9.37.94-2.11,1.17-5.63.48-7.52-.55-1.51-2.52-3.64-4.02-4.35-3.76-1.76-14.47-2.81-20.51-2m102.65,58.13c-2.09.66-2.93,3.41-1.52,4.96,1.39,1.52,3.84,1.65,5.33.28,1.9-1.75,1.18-4.39-1.43-5.3-.95-.33-1.17-.32-2.38.06m-124.56,14.38v13.7h6.06v-27.39h-6.06v13.7m112.98,0v13.7h4.62l.46-1.05.46-1.05.88.77c1.25,1.09,2.42,1.57,4.28,1.75,4.32.42,7.51-1.8,8.75-6.09.44-1.53.5-6.38.09-8.02-.34-1.37-1.46-3.48-2.27-4.28-.33-.33-1.16-.9-1.84-1.27-1.08-.59-1.54-.67-3.58-.67-2.58,0-3.57.33-5.15,1.71l-.88.77.17-4.98.17-4.98h-6.15v13.7m11.15-13.07c-.5.46-.68.9-.68,1.66,0,1.42.93,2.28,2.45,2.28.6,0,1.17-.11,1.27-.25s0-.25-.23-.25-.48-.29-.57-.63c-.1-.35-.36-.63-.58-.63-.25,0-.41.24-.41.63s-.16.63-.41.63c-.32,0-.41-.35-.41-1.64,0-1.55.04-1.65.71-1.81.94-.22,2.05.27,2.05.89,0,.27-.11.56-.25.64-.14.08-.06.49.18.94.41.75.45.77.8.33.58-.73.44-1.78-.34-2.63-.94-1.03-2.55-1.1-3.57-.16m1.25,1.03c0,.26.18.39.48.33.58-.1.54-.55-.05-.67-.25-.05-.43.09-.43.34m-201.16,12.96v12.83l6.54-.11c5.86-.1,6.71-.16,8.18-.66,2.34-.79,3.72-1.6,5.17-3.03,2.48-2.44,3.37-4.91,3.35-9.31-.01-2.45-.13-3.36-.62-4.69-1.13-3.06-2.98-5.03-6.05-6.45-2.43-1.13-4.53-1.4-10.85-1.4h-5.72s0,12.83,0,12.83m133.92-.02v12.81h6.34v-10.91h10.47v10.91h6.34v-25.62h-6.34v9.89h-10.47v-9.89h-6.34v12.81m-127.58,0v8.32l2.42-.13c3.78-.2,5.82-1.2,7.08-3.49.83-1.51,1.01-2.39,1.01-4.81,0-2.66-.62-4.57-1.91-5.89-1.43-1.47-2.9-1.99-6.01-2.16l-2.59-.14v8.32m27.58-6.84c-2.85.74-5.03,2.56-6.08,5.09-.95,2.27-1.09,6.31-.31,8.68,1.36,4.14,5.17,6.39,10.76,6.38,1.99,0,4.72-.42,6.1-.92l1.09-.4v-4.49l-1.86.65c-1.97.69-5.13,1.03-6.78.75-1.74-.3-3.17-1.74-3.61-3.64l-.19-.82h13.9l-.15-2.6c-.25-4.41-1.56-6.62-4.75-8.07-1.49-.68-2.16-.82-4.19-.9-1.62-.06-2.91.03-3.91.29m26.97-.16c-1.21.36-2.02.82-3.04,1.72l-.99.87-.35-1.16-.35-1.16h-4.89v28.15h6.14l-.14-5.22-.14-5.22.72.62c1.4,1.2,2.49,1.54,4.99,1.56,2.09,0,2.5-.07,3.8-.73,1.66-.85,2.81-2.15,3.7-4.19.54-1.24.61-1.87.61-5.34s-.07-4.09-.62-5.35c-.77-1.76-2.25-3.38-3.74-4.09-1.24-.59-4.46-.86-5.7-.49m32.91.02c-3.01.59-5.65,2.66-6.73,5.29-.75,1.82-1.01,5.54-.53,7.62.5,2.15,1.86,4.28,3.47,5.41,2.02,1.42,3.62,1.84,6.87,1.83,2.41-.01,2.97-.1,4.44-.72,2.09-.87,3.7-2.36,4.71-4.34.73-1.44.77-1.71.77-5.07s-.05-3.65-.73-4.98c-1.01-1.99-2.48-3.38-4.53-4.31-1.48-.67-2.13-.81-4.17-.88-1.33-.05-2.93.02-3.56.14m14.78.51c0,.14,1.87,4.55,4.15,9.8l4.15,9.55-.77,1.42c-1.08,1.98-2.11,2.56-4.53,2.56h-1.89v2.15c0,2.09.02,2.16.7,2.31.39.09,1.78.11,3.1.06,2-.09,2.65-.23,3.88-.85,1.72-.86,3.05-2.26,4.01-4.2.37-.76,2.54-5.94,4.81-11.52,2.27-5.58,4.26-10.46,4.42-10.84l.29-.7h-6.56l-2.22,6.18c-1.22,3.4-2.24,6.39-2.25,6.66-.02.26-.15.08-.3-.41-.15-.49-1.21-3.48-2.35-6.66l-2.07-5.77h-3.27c-1.99,0-3.27.1-3.27.25m54.56,6.71c0,7.74.18,9.03,1.47,10.61,1.37,1.68,3.09,2.33,6.1,2.33,2.73,0,4.73-.6,5.95-1.79.84-.82.98-.78,1.27.34l.24.95,2.4.07,2.4.07v-19.55h-6.03l-.09,6.15c-.08,5.55-.14,6.25-.64,7.16-1.36,2.5-5.13,2.96-6.43.78-.39-.66-.47-1.78-.55-7.43l-.09-6.66h-6.03v6.96m-127.45-3.17c-.75.29-1.69,1.26-2.05,2.12-.6,1.46-.63,1.44,3.6,1.44h3.89l-.18-.81c-.49-2.24-3.07-3.59-5.27-2.75m23.62.65c-1.45.58-1.98,1.97-1.98,5.2,0,3.88.88,5.37,3.37,5.75,1.48.22,2.81-.49,3.57-1.9.86-1.61.92-5.96.1-7.49-.94-1.76-2.98-2.38-5.06-1.55m35.63-.03c-1.8.73-2.49,2.23-2.46,5.35.03,3.98,1.27,5.58,4.33,5.58,1.51,0,1.68-.06,2.53-.92,1.6-1.61,2.02-5.94.8-8.24-.98-1.85-3.18-2.6-5.21-1.77m101.88.03c-1.45.58-1.98,1.97-1.98,5.2,0,3.94.92,5.45,3.49,5.74,2.3.26,3.89-1.66,4.14-4.97.35-4.72-2.15-7.37-5.65-5.97" style="fill: #fbfbfb; fill-rule: evenodd;"/>
                                </g>
                                </g>
                            </g>
                            </svg>
                            <div class="objname">{objname}</div>
                            <p class="rptdate">{rptdate}</p>
                        </div>
                    </div>
                </div>
        """  # nosec

        html_string = f"""
            <div id='details'>
                <h2>Federated Component Evidence Details</h2>
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
            </div>
            </div>
            </body>
            </html>
            """  # nocsec
        return HTMLResponse(content=cover_html + html_string)

    except HTTPException:
        raise
    except Exception as err:
        print(str(err))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(err)) from None


if __name__ == "__main__":
    uvicorn.run(app, port=5004)
