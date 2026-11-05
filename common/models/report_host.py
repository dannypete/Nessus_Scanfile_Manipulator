from sqlalchemy import Column, String, Integer, Boolean, DateTime, JSON, ForeignKey, ForeignKeyConstraint, UniqueConstraint
from sqlalchemy.orm import relationship

from .base import Base


class ReportHost(Base):
    __tablename__ = "report_host"

    name = Column(String, primary_key=True, unique=True)
    ip_address = Column(String, primary_key=True)
    fqdn = Column(String)
    json = Column(JSON)

    scans = relationship(
        "ReportHostScanMetadata",
        back_populates="report_host",
        cascade="all, delete-orphan"
    )

    findings = relationship(
        "ReportFinding",
        secondary="report_host_scan_metadata",
        primaryjoin="and_(ReportHost.name == ReportHostScanMetadata.report_host_name, "
                    "ReportHost.ip_address == ReportHostScanMetadata.report_host_ip_address)",
        secondaryjoin="ReportHostScanMetadata.id == ReportFinding.scan_id",
        viewonly=True
    )


class ReportHostScanMetadata(Base):
    __tablename__ = "report_host_scan_metadata"
    __table_args__ = (
        ForeignKeyConstraint(
            ["report_host_name", "report_host_ip_address"],
            ["report_host.name", "report_host.ip_address"]
        ),
        UniqueConstraint(
            "report_host_name", "report_host_ip_address",
            "scanner_type_name", "scan_start", "scan_end",
        )
    )

    id = Column(Integer, primary_key=True)
    report_host_name = Column(String, nullable=False)
    report_host_ip_address = Column(String, nullable=False)
    scanner_type_name = Column(String, ForeignKey("scanner_type.name"), nullable=False)

    credentialed_scan = Column(Boolean, default=False, nullable=False)
    scan_start = Column(DateTime, nullable=False)
    scan_end = Column(DateTime, nullable=False)
    scan_policy = Column(String, nullable=False)

    report_host = relationship("ReportHost", back_populates="scans")
    findings = relationship("ReportFinding", back_populates="scan", cascade="all, delete-orphan")
