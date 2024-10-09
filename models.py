import datetime
from settings import PG_DSN
from sqlalchemy import create_engine, Integer, String, DateTime, func, ForeignKey
from sqlalchemy.orm import sessionmaker, DeclarativeBase, Mapped, mapped_column

engine = create_engine(PG_DSN)
Session = sessionmaker(bind=engine)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = 'user'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(72), nullable=False)
    registration_time: Mapped[datetime.datetime] = mapped_column(DateTime, server_default=func.now())

    @property
    def dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "registration_time": self.registration_time.isoformat()
        }


class Adv(Base):
    __tablename__ = 'adv'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    header: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    owner_id: Mapped[int] = mapped_column(ForeignKey(User.id), index=True)
    registration_time: Mapped[datetime.datetime] = mapped_column(DateTime, server_default=func.now())
    @property
    def dict(self):
        return {
            "id": self.id,
            "header": self.header,
            "owner_id": self.owner_id,
            "registration_time": self.registration_time.isoformat()
        }





Base.metadata.create_all(bind=engine)
