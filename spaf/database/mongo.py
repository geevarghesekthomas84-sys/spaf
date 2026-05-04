import os
from typing import Any, Dict, List, Optional
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
from datetime import datetime
from spaf.utils.logger import logger

# MongoDB Configuration
MONGO_URI = os.getenv("SPAF_MONGO_URI", "mongodb://localhost:27017")
MONGO_DB = os.getenv("SPAF_MONGO_DB", "spaf")

class MongoDB:
    def __init__(self):
        self.client: Optional[AsyncIOMotorClient] = None
        self.db = None

    async def connect(self):
        """
        Initializes the MongoDB connection and ensures indexes.
        """
        try:
            self.client = AsyncIOMotorClient(MONGO_URI, serverSelectionTimeoutMS=2000)
            self.db = self.client[MONGO_DB]
            # Verify connection
            await self.client.admin.command('ping')
            await self._ensure_indexes()
            logger.info(f"Connected to MongoDB at {MONGO_URI}")
        except Exception as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            raise ConnectionError(f"Could not connect to MongoDB at {MONGO_URI}. Ensure MongoDB is running.")

    async def _ensure_indexes(self):
        """
        Creates necessary indexes for performance and uniqueness.
        """
        # Unique index on target domain
        await self.db.targets.create_index("domain", unique=True)
        
        # Compound index on scans for target lookup
        await self.db.scans.create_index([("target", 1), ("started_at", -1)])
        
        # Unique compound index on vulnerabilities to prevent duplicates
        await self.db.vulnerabilities.create_index(
            [("scan_id", 1), ("vuln_type", 1), ("target", 1)],
            unique=True
        )
        logger.debug("Database indexes verified.")

    async def upsert_target(self, domain: str, metadata: Optional[Dict[str, Any]] = None):
        """
        Creates or updates a target entry.
        """
        now = datetime.utcnow()
        update_data = {
            "$set": {
                "updated_at": now,
                **(metadata or {})
            },
            "$setOnInsert": {
                "created_at": now,
                "domain": domain
            }
        }
        await self.db.targets.update_one({"domain": domain}, update_data, upsert=True)

    async def create_scan(self, target: str, scan_type: str, options: Dict[str, Any]) -> str:
        """
        Records the start of a new scan.
        """
        scan_doc = {
            "target": target,
            "type": scan_type,
            "status": "running",
            "options": options,
            "started_at": datetime.utcnow(),
            "completed_at": None,
            "findings_count": 0,
            "error": None
        }
        result = await self.db.scans.insert_one(scan_doc)
        return str(result.inserted_id)

    async def complete_scan(self, scan_id: str, findings_count: int):
        """
        Marks a scan as completed.
        """
        await self.db.scans.update_one(
            {"_id": ObjectId(scan_id)},
            {
                "$set": {
                    "status": "completed",
                    "completed_at": datetime.utcnow(),
                    "findings_count": findings_count
                }
            }
        )

    async def fail_scan(self, scan_id: str, error: str):
        """
        Marks a scan as failed with an error message.
        """
        await self.db.scans.update_one(
            {"_id": ObjectId(scan_id)},
            {
                "$set": {
                    "status": "failed",
                    "completed_at": datetime.utcnow(),
                    "error": error
                }
            }
        )

    async def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves a single scan document.
        """
        return await self.db.scans.find_one({"_id": ObjectId(scan_id)})

    async def get_scan_history(self, target: Optional[str] = None, limit: int = 20) -> List[Dict[str, Any]]:
        """
        Retrieves scan history, optionally filtered by target.
        """
        query = {"target": target} if target else {}
        cursor = self.db.scans.find(query).sort("started_at", -1).limit(limit)
        return await cursor.to_list(length=limit)

    async def get_latest_scans_for_target(self, target: str) -> List[Dict[str, Any]]:
        """
        Retrieves the latest scan for each scan type for a given target.
        """
        pipeline = [
            {"$match": {"target": target}},
            {"$sort": {"started_at": -1}},
            {
                "$group": {
                    "_id": "$type",
                    "latest_scan": {"$first": "$$ROOT"}
                }
            }
        ]
        cursor = self.db.scans.aggregate(pipeline)
        results = await cursor.to_list(length=10)
        return [r["latest_scan"] for r in results]

    async def upsert_vulnerability(self, scan_id: str, vuln_dict: Dict[str, Any]):
        """
        Inserts or updates a vulnerability record, deduplicating by scan_id+vuln_type+target.
        """
        vuln_dict["scan_id"] = scan_id
        now = datetime.utcnow()
        vuln_dict["updated_at"] = now
        # Remove created_at from the $set payload to avoid a path conflict
        # with $setOnInsert when MongoDB processes both operators on the same field.
        vuln_dict.pop("created_at", None)

        filter_query = {
            "scan_id": scan_id,
            "vuln_type": vuln_dict["vuln_type"],
            "target": vuln_dict["target"]
        }

        update_data = {
            "$set": vuln_dict,
            "$setOnInsert": {"created_at": now}
        }
        
        await self.db.vulnerabilities.update_one(filter_query, update_data, upsert=True)

    async def get_vulnerabilities_for_scan(self, scan_id: str) -> List[Dict[str, Any]]:
        """
        Retrieves all findings for a specific scan.
        """
        cursor = self.db.vulnerabilities.find({"scan_id": scan_id}).sort("severity_order", 1)
        return await cursor.to_list(length=1000)

    async def get_all_vulnerabilities_for_target(self, target: str) -> List[Dict[str, Any]]:
        """
        Retrieves all unique findings for a target across all scans.
        """
        pipeline = [
            {"$match": {"target": target}},
            {"$sort": {"severity_order": 1, "created_at": -1}},
            {
                "$group": {
                    "_id": "$vuln_type",
                    "latest_finding": {"$first": "$$ROOT"}
                }
            },
            {"$replaceRoot": {"newRoot": "$latest_finding"}},
            {"$sort": {"severity_order": 1}}
        ]
        cursor = self.db.vulnerabilities.aggregate(pipeline)
        return await cursor.to_list(length=1000)

    async def get_finding(self, finding_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves a specific vulnerability finding by its ID.
        """
        try:
            return await self.db.vulnerabilities.find_one({"_id": ObjectId(finding_id)})
        except Exception:
            return None

# Single instance for the application
db = MongoDB()
