from typing import Annotated, Optional

from fastapi import Depends

from app.models.user import UserInDB
from app.database import CollectionsNames, MongoDep

from app.utils.common import cuid_generator
from app.utils.encryption import encrypt_data, decrypt_data


class UserServices:
    def __init__(self, db: MongoDep) -> None:
        self._db = db
        self._collection = CollectionsNames.USERS

    def __call__(self):
        return self

    def get_user_by_username(self, username: str) -> dict | None:
        return self._db.find_one(
            {"username": username},
            self._collection
        )

    def get_user_by_id(self, user_id: str) -> Optional[UserInDB]:
        user = self._db.find_one(
            {"user_id": user_id},
            self._collection
        )

        if not user:
            return None

        # Decrypt sensitive data
        if user.get("zkp_commitment"):
            user["zkp_commitment"] = decrypt_data(user["zkp_commitment"])

        return user

    def username_exist(self, username: str) -> bool:
        user_result = self._db.find_one_with_projection(
            {"username": username}, self._collection, {"username": 1}
        )

        return user_result is not None

    def update_user_by_id(self, user_id: str, data: dict):
        self._db.update_one(
            {"user_id": user_id},
            {"$set": data},
            self._collection,
        )

    def create_user(self, username: str, contact_email: str, zkp_commitment: bytes) -> str:

        user = UserInDB(
            user_id=cuid_generator(),
            username=username,
            contact_email=contact_email,
            zkp_commitment=encrypt_data(zkp_commitment)
        )

        self._db.insert_one(user.model_dump(), self._collection)

        return user.user_id


UsersSvc = Annotated[UserServices, Depends()]
