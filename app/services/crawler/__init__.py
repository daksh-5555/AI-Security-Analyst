"""Safe crawler for explicitly authorized web targets (M5, ADR-0008)."""

from app.services.crawler.tool import CRAWL_STAGE, CrawlerTool

__all__ = ["CRAWL_STAGE", "CrawlerTool"]
