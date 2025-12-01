"""Database models for Security Scanner Platform"""
from sqlalchemy import Column, Integer, String, DateTime, JSON, Float, Boolean, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime

Base = declarative_base()


class ScanRecord(Base):
    """Store individual scan records"""
    __tablename__ = "scan_records"
    
    id = Column(Integer, primary_key=True, index=True)
    target_url = Column(String(500), nullable=False, index=True)
    scanner_name = Column(String(100), nullable=False, index=True)
    scan_date = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    duration = Column(Float, nullable=False)  # seconds
    status = Column(String(20), nullable=False)  # "completed", "failed", "timeout"
    results = Column(JSON, nullable=False)  # Full scan results
    summary = Column(JSON, nullable=False)  # Severity counts
    scan_metadata = Column(JSON, nullable=True)  # Additional scanner-specific data
    
    # Relationships
    history_entries = relationship("ScanHistory", back_populates="scan_record")


class ScanHistory(Base):
    """Track scan history for analytics"""
    __tablename__ = "scan_history"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_record_id = Column(Integer, ForeignKey("scan_records.id"), nullable=False)
    target_url = Column(String(500), nullable=False, index=True)
    scanner_name = Column(String(100), nullable=False)
    scan_date = Column(DateTime, default=datetime.utcnow, nullable=False)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    total_checks = Column(Integer, default=0)
    passed_checks = Column(Integer, default=0)
    failed_checks = Column(Integer, default=0)
    
    # Relationships
    scan_record = relationship("ScanRecord", back_populates="history_entries")


class ScheduledScan(Base):
    """Scheduled scan configurations"""
    __tablename__ = "scheduled_scans"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)
    target_url = Column(String(500), nullable=False)
    scanner_names = Column(JSON, nullable=False)  # List of scanner names
    schedule_cron = Column(String(100), nullable=False)  # Cron expression
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_run = Column(DateTime, nullable=True)
    next_run = Column(DateTime, nullable=True)
    notification_email = Column(String(200), nullable=True)
    notification_webhook = Column(String(500), nullable=True)


class ScanComparison(Base):
    """Store scan comparisons for tracking changes"""
    __tablename__ = "scan_comparisons"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)
    target_url = Column(String(500), nullable=False)
    scanner_name = Column(String(100), nullable=False)
    baseline_scan_id = Column(Integer, ForeignKey("scan_records.id"))
    current_scan_id = Column(Integer, ForeignKey("scan_records.id"))
    comparison_date = Column(DateTime, default=datetime.utcnow)
    changes = Column(JSON, nullable=False)  # {"improved": [], "degraded": [], "new": [], "removed": []}
    notes = Column(Text, nullable=True)


class AuditLog(Base):
    """Audit trail for security and compliance"""
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    action = Column(String(100), nullable=False)  # "scan_started", "scan_completed", "scan_failed", etc.
    user = Column(String(100), nullable=True)
    target_url = Column(String(500), nullable=True)
    scanner_name = Column(String(100), nullable=True)
    details = Column(JSON, nullable=True)
    ip_address = Column(String(50), nullable=True)
