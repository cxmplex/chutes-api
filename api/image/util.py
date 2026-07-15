import re
import uuid
from sqlalchemy import or_
from sqlalchemy.future import select
from api.image.schemas import Image
from api.user.schemas import User
from api.database import get_session


def image_id_for(username: str, name: str, tag: str, compute_type: str) -> str:
    """Canonical image identity shared with the SDK build contract."""
    normalized_compute = str(compute_type).lower()
    if normalized_compute not in {"cpu", "gpu"}:
        raise ValueError("compute_type must be 'cpu' or 'gpu'")
    identity = f"{username.lower()}/{name}:{tag}:{normalized_compute}".lower()
    return str(uuid.uuid5(uuid.NAMESPACE_OID, identity))


async def get_image_by_id_or_name(image_id_or_name, db, current_user):
    """
    Helper to load an image by ID or full image name (optional username/image name:image tag)
    """
    name_match = re.match(
        r"(?:([a-z0-9][a-z0-9_\.-]*)/)?([a-z0-9][a-z0-9_\.-]*):([a-z0-9][a-z0-9_\.-]*)$",
        image_id_or_name.lstrip("/"),
        re.I,
    )
    query = (
        select(Image)
        .join(User, Image.user_id == User.user_id)
        .where(or_(Image.public.is_(True), Image.user_id == current_user.user_id))
    )
    if name_match:
        username = name_match.group(1) or current_user.username
        image_name = name_match.group(2)
        tag = name_match.group(3)
        query = (
            query.where(User.username == username)
            .where(Image.name == image_name)
            .where(Image.tag == tag)
        )
    else:
        query = query.where(Image.image_id == image_id_or_name)
    result = await db.execute(query)
    return result.scalar_one_or_none()


async def get_inspecto_hash(image_id: str):
    async with get_session(readonly=True) as session:
        return (
            (await session.execute(select(Image.inspecto).where(Image.image_id == image_id)))
            .unique()
            .scalar_one_or_none()
        )
