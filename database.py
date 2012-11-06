# Copyright (c) 2012, Claudio "nex" Guarnieri
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Enum, ForeignKey, Table
from sqlalchemy.orm import relationship, backref, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.exc import SQLAlchemyError, IntegrityError

from objects import File, Config

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
    file_type = Column(String(255), nullable=False)
    md5 = Column(String(32), unique=True, nullable=False, index=True)
    crc32 = Column(String(8), unique=True, nullable=False)
    sha1 = Column(String(40), unique=True, nullable=False)
    sha256 = Column(String(64), unique=True, nullable=False, index=True)
    sha512 = Column(String(128), unique=True, nullable=False)
    ssdeep = Column(String(255), nullable=True)
    tag = relationship("Tag",
                       secondary=association_table,
                       backref="malware")

    def to_dict(self):
        d = {}
        for column in self.__table__.columns:
            value = getattr(self, column.name)
            d[column.name] = value
        return d

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
                 file_name=None):
        self.md5 = md5
        self.sha1 = sha1
        self.crc32 = crc32
        self.sha256 = sha256
        self.sha512 = sha512
        self.file_size = file_size
        if file_type:
            self.file_type = file_type
        if ssdeep:
            self.ssdeep = ssdeep
        if file_name:
            self.file_name = file_name

class Tag(Base):
    __tablename__ = "tag"

    id = Column(Integer(), primary_key=True)
    tag = Column(String(255), nullable=False, unique=True, index=True)

    def to_dict(self):
        d = {}
        for column in self.__table__.columns:
            value = getattr(self, column.name)
            d[column.name] = value
        return d

    def __repr__(self):
        return "<Tag ('%s','%s'>" % (self.id, self.tag)

    def __init__(self, tag):
        self.tag = tag

class Database:
    def __init__(self):
        engine = create_engine(Config().api.database)
        engine.echo = False
        engine.pool_timeout = 60

        Base.metadata.create_all(engine)
        self.Session = sessionmaker(bind=engine)

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
                                        file_name=file_name)
                session.add(malware_entry)
                session.commit()
            except IntegrityError:
                session.rollback()
                malware_entry = session.query(Malware).filter(Malware.md5 == obj.get_md5()).first()

        if tags:
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
                    except:
                        session.rollback()
                        # TODO: OMG cannot tag!

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

    def list_tags(self):
        session = self.Session()
        rows = session.query(Tag).all()
        return rows