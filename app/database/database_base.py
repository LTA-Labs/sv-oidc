from abc import abstractmethod
from dataclasses import dataclass
from typing import Any, Iterable, Literal, Protocol


@dataclass
class PaginatedDBResult:
    data: Iterable[dict]
    has_next: bool


class BaseDatabaseService(Protocol):
    @abstractmethod
    def insert_one(self, data: dict, collection: str) -> str:
        raise NotImplementedError

    @abstractmethod
    def update_one(
        self, filters: dict, data: dict, collection: str, upsert=False
    ) -> None:
        raise NotImplementedError

    @abstractmethod
    def update_many(
        self, filters: dict, data: dict, collection: str, upsert=False
    ) -> None:
        raise NotImplementedError

    @abstractmethod
    def find(self, filters: dict, collection: str) -> Iterable[dict]:
        raise NotImplementedError

    @abstractmethod
    def paginated_find(
        self,
        filters: dict,
        page: int,
        page_size: int,
        collection: str,
        sort_by: str = "_id",
        sort_direction: Literal[1, -1] = -1,
    ) -> PaginatedDBResult:
        raise NotImplementedError

    @abstractmethod
    def find_with_projection(
        self, filters: dict, collection: str, projection: dict
    ) -> Iterable[dict]:
        raise NotImplementedError

    @abstractmethod
    def find_one(self, filters: dict, collection: str) -> dict | None:
        raise NotImplementedError

    @abstractmethod
    def find_one_with_projection(
        self, filters: dict, collection: str, projection: dict
    ) -> dict | None:
        raise NotImplementedError

    @abstractmethod
    def ping(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def delete_one(self, filters: dict, collection: str) -> None:
        raise NotImplementedError

    @abstractmethod
    def aggregation(self, data: list[dict], collection: str) -> Any:
        raise NotImplementedError
