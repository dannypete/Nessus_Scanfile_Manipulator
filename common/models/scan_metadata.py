from sqlalchemy import String, Column, DateTime

from .base import Base


class ScanJob(Base):
    __tablename__ = "scan_job"

    file_name = Column(String, primary_key=True)
    scan_name = Column(String, nullable=False)

    scan_start = Column(DateTime, nullable=False)
    scan_end = Column(DateTime, nullable=False)
    scan_profile = Column(String, nullable=False)  # e.g. "Basic Network Scan"


