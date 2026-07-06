import hashlib
from functools import cached_property
from pathlib import Path
from sqlmodel import Field, SQLModel, Session, create_engine, select


class WazuhAgent(SQLModel, table=True):
    __tablename__ = "agents"  # pyright: ignore[reportAssignmentType]

    id: int | None = Field(default=None, primary_key=True)
    key: bytes
    name: str
    version: str

    @cached_property
    def aes_key(self) -> bytes:
        return hashlib.md5(self.key).hexdigest().encode()


class WazuhAgentRepository:
    def __init__(self, db_path: str | Path = "agents.db") -> None:
        self.engine = create_engine(f"sqlite:///{db_path}")
        with self.engine.connect() as conn:
            conn.exec_driver_sql("PRAGMA journal_mode=WAL")
        SQLModel.metadata.create_all(self.engine)
        self._cache: dict[int, WazuhAgent] = {
            a.id: a for a in self._fetch_all() if a.id is not None
        }

    def _fetch_all(self) -> list[WazuhAgent]:
        with Session(self.engine) as session:
            return list(session.exec(select(WazuhAgent)))

    def add(self, agent: WazuhAgent) -> WazuhAgent:
        with Session(self.engine) as session:
            session.add(agent)
            session.commit()
            session.refresh(agent)
        assert agent.id is not None
        self._cache[agent.id] = agent
        return agent

    def get(self, id: int) -> WazuhAgent | None:
        agent = self._cache.get(id)
        if agent is None:
            with Session(self.engine) as session:
                agent = session.get(WazuhAgent, id)
            if agent is not None:
                assert agent.id is not None
                self._cache[agent.id] = agent
        return agent

    def all(self) -> list[WazuhAgent]:
        return list(self._cache.values())
