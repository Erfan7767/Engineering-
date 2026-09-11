"""Reporting subsystem — HTML and JSON renderers for run artifacts."""
from .html_report import render_html_report, ReportData
from .json_report import render_json_report

__all__ = ["render_html_report", "ReportData", "render_json_report"]
