from sqlalchemy import select
from sqlalchemy.orm import DeclarativeBase, Session

class Base(DeclarativeBase):

    @classmethod
    def get_or_create(cls, session: Session, defaults: dict | None = None, **keys):
        obj = session.scalars(select(cls).filter_by(**keys)).one_or_none()
        if obj is None:
            obj = cls(**keys, **(defaults or {}))
            session.add(obj)
        return obj
