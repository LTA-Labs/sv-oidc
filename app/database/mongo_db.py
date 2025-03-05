from enum import StrEnum
from typing import Annotated, Any, Iterable, Literal, Optional

from fastapi import Depends
from pymongo import DESCENDING, MongoClient

from app.config import settings
from app.database.database_base import BaseDatabaseService, PaginatedDBResult

CLIENT = MongoClient(settings.DATABASE_URL)
DB = CLIENT[settings.DATABASE_NAME]


class CollectionsNames(StrEnum):
    USERS = "users"
    SESSIONS = "sessions"


class MongoDatabase(BaseDatabaseService):
    def __call__(self) -> BaseDatabaseService:
        return self

    def ping(self) -> None:
        DB.command("ping")

    def insert_one(self, data: dict, collection: str) -> str:
        return DB[collection].insert_one(data).inserted_id

    def update_one(
        self, filters: dict, data: dict, collection: str, upsert=False
    ) -> None:
        DB[collection].update_one(filters, data, upsert=upsert)

    def update_many(
        self, filters: dict, data: dict, collection: str, upsert=False
    ) -> None:
        DB[collection].update_many(filters, data, upsert=upsert)

    def find(self, filters: dict, collection: str) -> Iterable[dict]:
        return DB[collection].find(filters)

    def find_with_projection(
        self, filters: dict, collection: str, projection: dict
    ) -> Iterable[dict]:
        return DB[collection].find(filters, projection=projection)

    def find_one(self, filters: dict, collection: str) -> Optional[dict]:
        return DB[collection].find_one(filters)

    def find_one_with_projection(
        self, filters: dict, collection: str, projection: dict
    ) -> Optional[dict]:
        return DB[collection].find_one(filters, projection=projection)

    def delete_one(self, filters: dict, collection: str) -> None:
        DB[collection].delete_one(filters)

    def paginated_find(
        self,
        filters: dict,
        page: int,
        page_size: int,
        collection: str,
        sort_by: str = "_id",
        sort_direction: Literal[1, -1] = DESCENDING,
    ) -> PaginatedDBResult:
        result = list(
            DB[collection]
            .find(filters)
            .skip(page * page_size)
            .limit(page_size + 1)
            .sort(sort_by, sort_direction)
        )
        has_next = len(result) > page_size
        return PaginatedDBResult(data=result[:page_size], has_next=has_next)

    def aggregation(self, data: list[dict], collection: str) -> Any:
        return DB[collection].aggregate(data)


MongoDB = MongoDatabase()
MongoDep = Annotated[BaseDatabaseService, Depends(MongoDB)]
