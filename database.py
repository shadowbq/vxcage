# -*- coding: utf-8 -*-

from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Enum, Text, ForeignKey, Table, Index, and_, or_, func
from sqlalchemy.orm import relationship, backref, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.pool import NullPool
from sqlalchemy.dialects import postgresql

from objects import File, Config
from datetime import datetime

Base = declarative_base()

association_table = Table('association', Base.metadata,
    Column('tag_id', Integer, ForeignKey('tag.id')),
    Column('malware_id', Integer, ForeignKey('malware.id'))
)

class Malware(Base):
    __tablename__ = "malware"

    id = Column(Integer(), primary_key=True)
    file_name = Column(String(255), nullable=True)
    file_size = Column(Integer(), nullable=False)
    file_type = Column(Text(), nullable=True)
    md5 = Column(String(32), nullable=False, index=True)
    crc32 = Column(String(8), nullable=False)
    sha1 = Column(String(40), nullable=False)
    sha256 = Column(String(64), nullable=False, index=True)
    sha512 = Column(String(128), nullable=False)
    ssdeep = Column(String(255), nullable=True)
    imphash= Column(String(32), nullable=True)
    virustotal = Column(postgresql.JSON(), nullable=True)
    exif = Column(postgresql.JSON(), nullable=True)
    peheaders = Column(postgresql.JSON(), nullable=True)
    peid = Column(Text(), nullable=True)
    pdfid = Column(postgresql.JSON(), nullable=True)
    created_at = Column(DateTime(timezone=False), default=datetime.now(), nullable=False)
    tag = relationship("Tag",
                       secondary=association_table,
                       backref="malware")
    __table_args__ = (Index("hash_index",
                            "md5",
                            "crc32",
                            "sha1",
                            "sha256",
                            "sha512",
                            unique=True), )

    def to_dict(self):
        row_dict = {}
        for column in self.__table__.columns:
            value = getattr(self, column.name)
            row_dict[column.name] = value

        return row_dict

    def __repr__(self):
        return "<Malware('%s','%s')>" % (self.id, self.md5)

    def __init__(self,
                 md5,
                 crc32,
                 sha1,
                 sha256,
                 sha512,
                 file_size,
                 file_type=None,
                 ssdeep=None,
                 imphash=None,
		         virustotal=None,
		         exif=None,
		         peheaders=None,
		         peid=None,
		         pdfid=None,
                 file_name=None):
        self.md5 = md5
        self.sha1 = sha1
        self.crc32 = crc32
        self.sha256 = sha256
        self.sha512 = sha512
        self.file_size = file_size
        self.file_type = file_type
        self.ssdeep = ssdeep
        self.imphash = imphash 
        self.virustotal= virustotal
        self.exif = exif
        self.peheaders = peheaders
        self.peid = peid
        self.pdfid = pdfid
        self.file_name = file_name

class Tag(Base):
    __tablename__ = "tag"

    id = Column(Integer(), primary_key=True)
    tag = Column(String(255), nullable=False, unique=True, index=True)

    def to_dict(self):
        row_dict = {}
        for column in self.__table__.columns:
            value = getattr(self, column.name)
            row_dict[column.name] = value

        return row_dict

    def __repr__(self):
        return "<Tag ('%s','%s'>" % (self.id, self.tag)

    def __init__(self, tag):
        self.tag = tag

class Singleton(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]

class Database:

    __metaclass__ = Singleton

    def __init__(self):
        self.engine = create_engine(Config().api.database, poolclass=NullPool)
        self.engine.echo = False
        self.engine.pool_timeout = 60

        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def __del__(self):
        self.engine.dispose()

    def add(self, obj, file_name, tags=None):
        session = self.Session()

        if isinstance(obj, File):
            try:
                malware_entry = Malware(md5=obj.get_md5(),
                                        crc32=obj.get_crc32(),
                                        sha1=obj.get_sha1(),
                                        sha256=obj.get_sha256(),
                                        sha512=obj.get_sha512(),
                                        file_size=obj.get_size(),
                                        file_type=obj.get_type(),
                                        ssdeep=obj.get_ssdeep(),
                                        imphash=obj.get_imphash(),
                                        virustotal=obj.get_virustotal(),
                                        exif=obj.get_exif(),
                                        peheaders=obj.get_peheaders(),
                                        peid=obj.get_peid(),
                                        pdfid=obj.get_pdfid(),
                                        file_name=file_name)
                session.add(malware_entry)
                session.commit()
            except IntegrityError:
                session.rollback()
                malware_entry = session.query(Malware).filter(Malware.md5 == obj.get_md5()).first()
            except SQLAlchemyError:
                session.rollback()
                return False

        if tags:
            tags = tags.strip()
            if "," in tags:
                tags = tags.split(",")
            else:
                tags = tags.split(" ")

            for tag in tags:
                tag = tag.strip().lower()
                if tag == "":
                    continue

                try:
                    malware_entry.tag.append(Tag(tag))
                    session.commit()
                except IntegrityError as e:
                    session.rollback()
                    try:
                        malware_entry.tag.append(session.query(Tag).filter(Tag.tag==tag).first())
                        session.commit()
                    except SQLAlchemyError:
                        session.rollback()

        return True

    def find_md5(self, md5):
        session = self.Session()
        row = session.query(Malware).filter(Malware.md5 == md5).first()
        return row

    def find_sha256(self, sha256):
        session = self.Session()
        row = session.query(Malware).filter(Malware.sha256 == sha256).first()
        return row

    def find_tag(self, tag):
        session = self.Session()
        rows =  session.query(Malware).filter(Malware.tag.any(Tag.tag == tag.lower())).all()
        return rows

    def find_ssdeep(self, ssdeep):
        session = self.Session()
        rows = session.query(Malware).filter(Malware.ssdeep.like("%" + str(ssdeep) + "%")).all()
        return rows

    def find_imphash(self, imphash):
        session = self.Session()
        row = session.query(Malware).filter(Malware.imphash == imphash).all()
        return rows

    def find_date(self, date):
        session = self.Session()

        date_min = datetime.strptime(date, "%Y-%m-%d")
        date_max = date_min.replace(hour=23, minute=59, second=59)

        rows = session.query(Malware).filter(and_(Malware.created_at >= date_min, Malware.created_at <= date_max)).all()
        return rows

    def list_tags(self):
        session = self.Session()
        rows = session.query(Tag).all()
        return rows
    
    def vt_error(self):
        session = self.Session()
        rows = session.query(Malware).filter(Malware.virustotal['virustotal'].cast(Integer) == -1).all()
        return rows

    def vt_missing(self):
        session = self.Session()
        rows = session.query(Malware).filter(Malware.virustotal['virustotal'].cast(Integer) == 0).all()
        return rows
    
    def total_samples(self):
        session = self.Session()
        rows = session.query(func.count(Malware.md5)).scalar()
        return rows
