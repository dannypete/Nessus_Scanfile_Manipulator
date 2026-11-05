from sqlalchemy import Column, ForeignKey, String, Integer, CheckConstraint, ForeignKeyConstraint
from sqlalchemy.ext.associationproxy import association_proxy
from sqlalchemy.orm import validates, relationship

from .base import Base


class ReportFinding(Base):
    __tablename__ = "report_finding"
    __table_args__ = (
         ForeignKeyConstraint(
              ["scanner_plugin_plugin_id", "scanner_plugin_scanner_name"],
              ["scanner_plugin.plugin_id", "scanner_plugin.scanner_type_name"]
         ),
    )

    scan_id = Column(Integer, ForeignKey("report_host_scan_metadata.id"), primary_key=True)
    scanner_plugin_plugin_id = Column(String, primary_key=True)
    scanner_plugin_scanner_name = Column(String, primary_key=True)
    protocol = Column(String, primary_key=True)
    port = Column(Integer, CheckConstraint('port > -1 AND 65536 > port'), primary_key=True, nullable=False)

    title = Column(String, nullable=False)
    description = Column(String)
    severity = Column(Integer, CheckConstraint('severity > -1 AND 5 > severity'))
    solution = Column(String)
    plugin_output = Column(String)

    scan = relationship("ReportHostScanMetadata", back_populates="findings")
    scanner_plugin = relationship("ScannerPlugin", back_populates="findings")

    report_host = association_proxy("scan", "report_host")

    @validates
    def validate_port(self, key, value):
        if not 65536 > value > -1:
            raise ValueError(f'Invalid report_finding.port: {key}={value}')
        return value

    @validates('severity')
    def validate_severity(self, key, value):
        if not 0 <= value <= 4:
            raise ValueError(f'Invalid report_finding.severity: {key}={value}')
        return value


class ScannerType(Base):
    __tablename__ = "scanner_type"

    name = Column(String, primary_key=True, unique=True)

    plugins = relationship("ScannerPlugin", back_populates="scanner_type")
         

SCANNER_PLUGIN_SEQUENCE = "scanner_plugin_sequence"

class ScannerPlugin(Base):
    __tablename__ = "scanner_plugin"

    plugin_id = Column(String, primary_key=True)
    scanner_type_name = Column(String, ForeignKey("scanner_type.name"), primary_key=True)
    plugin_type = Column(String)

    scanner_type = relationship("ScannerType", back_populates="plugins")
    findings = relationship("ReportFinding", back_populates="scanner_plugin")
