from fastapi import APIRouter

router = APIRouter()

@router.get("/")
async def topology():
    from app.discovery.crawler import crawler
    from app.topology.mapper import mapper
    # If no discovery yet, return lab example
    if not crawler.devices:
        return {
            "nodes": [],
            "edges": [],
            "message": "لا توجد طوبولوجيا بعد — شغّل الاكتشاف من seedDevice أولاً. أي جهاز لا يصل عبر LLDP/CDP سيُعلن فشلاً صريحاً.",
            "evidenceBased": True
        }
    # build from current crawler state
    from app.discovery.crawler import DiscoveryResult
    result = DiscoveryResult(
        devices=list(crawler.devices.values()),
        links=crawler.links,
        evidence={"records": {}},
        failures=crawler.failures,
        sites=[]
    )
    return mapper.build(result)
