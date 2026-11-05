import datetime
import lxml.etree as ET
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from common.models.report_finding import ReportFinding, ScannerPlugin, ScannerType
from common.models.report_host import ReportHost, ReportHostScanMetadata

from common.utils import get_xml_context_from_file, get_nessus_hostproperty_by_name, str_to_bool
from common.models.base import Base

# url = "sqlite:///testing.db"
# url = "sqlite://"
ENGINE = None

# for now, only Nessus scans
SCANNER = "TenableNessusPro"


def init_db(url="", echo=False):
    global ENGINE 
    url = f"sqlite:///{url}"
    ENGINE = create_engine(url=url, echo=echo)
    Base.metadata.create_all(ENGINE)


def insert_scan_details(args, input_file: str):
    context = get_xml_context_from_file(args, input_file=input_file, tag="ReportHost")

    with Session(ENGINE) as session:

        ScannerType.get_or_create(session, name=SCANNER)

        for _, host in context:
            hostprops = host.find("HostProperties")
            ip = get_nessus_hostproperty_by_name(hostprops, "host-ip")
            fqdn = get_nessus_hostproperty_by_name(hostprops, "host-fqdn", None)
            reported_name = host.get("name", None)
            tags = dict()
            for tag in hostprops:
                tags[tag.get("name").lower()] = tag.text

            is_host_and_scan_created = False

            for _, finding in ET.iterwalk(host, tag="ReportItem"):
                port = finding.get("port")
                protocol = finding.get("protocol")
                service = finding.get("svc_name")
                plugin_name = finding.get("pluginName").replace("\n", "\\n")
                plugin_id = finding.get("pluginID")
                severity = int(finding.get("severity"))
                plugin_output = finding.find("plugin_output").text.replace("\n", "\\n") if finding.find("plugin_output") is not None else ''
                description = finding.find("description").text.replace("\n", "\\n")
                solution = finding.find("solution").text.replace("\n", "\\n")
                risk = finding.find("risk_factor").text
                plugin_type = finding.find("plugin_type").text


                if not is_host_and_scan_created:
                    report_host_name = reported_name or fqdn or ip
            
                    ReportHost.get_or_create(
                        session, 
                        name=report_host_name,
                        ip_address=ip,
                        defaults=dict(
                            fqdn=fqdn,
                            json=tags
                        )
                    )

                    scan = ReportHostScanMetadata.get_or_create(
                        session,
                        report_host_name=report_host_name,
                        report_host_ip_address=ip,
                        scanner_type_name=SCANNER,
                        scan_start=datetime.datetime.fromtimestamp(int(tags['host_start_timestamp'])),
                        scan_end=datetime.date.fromtimestamp(int(tags['host_end_timestamp'])),
                        defaults=dict(
                            credentialed_scan=str_to_bool(tags['credentialed_scan']),
                            scan_policy=tags['policy-used']
                        )
                    )

                    session.flush()
                    is_host_and_scan_created = True

                ScannerPlugin.get_or_create(
                    session,
                    plugin_id=plugin_id,
                    scanner_type_name=SCANNER,
                    defaults=dict(
                        plugin_type=plugin_type
                    )
                )

                ReportFinding.get_or_create(
                    session,
                    scan_id=scan.id,
                    scanner_plugin_plugin_id=plugin_id,
                    scanner_plugin_scanner_name=SCANNER,
                    protocol=protocol,
                    port=port,
                    defaults=dict(
                        title=plugin_name,
                        description=description,
                        severity=severity,
                        solution=solution,
                        plugin_output=plugin_output
                    )
                )

                session.commit()


def is_scan_already_ingested(input_file: str):
    with Session(ENGINE) as session:
        obj = session.scalars(select())