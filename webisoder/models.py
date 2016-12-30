# webisoder
# Copyright (C) 2006-2016  Stefan Ott
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from random import SystemRandom
from string import digits, ascii_lowercase, ascii_uppercase
from datetime import datetime, date

from sqlalchemy import Boolean, Column, Date, DateTime, Integer, String, Numeric
from sqlalchemy import Table, ForeignKey, Index, UniqueConstraint, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.orm import relationship

from hashlib import md5
from bcrypt import hashpw, gensalt

from zope.sqlalchemy import ZopeTransactionExtension

DBSession = scoped_session(sessionmaker(extension=ZopeTransactionExtension()))
Base = declarative_base()

subscriptions = Table('subscriptions', Base.metadata,
	Column('show_id', Integer, ForeignKey('shows.show_id'),
		nullable=False),
	Column("user_name", String(30), ForeignKey("users.user_name"),
		nullable=False),
	UniqueConstraint("show_id", "user_name")
)

# This is unused in webisoder
meta = Table("meta", Base.metadata,
	Column("key", Text, primary_key=True),
	Column("value", Text))

# Also unused
# news = Table("news", ...


class ResultRating(float):

	def __new__(self, search_o, val_o):

		search = search_o.lower()
		val = val_o.lower()
		res = 0

		if search == val:
			res = 1
		elif val.endswith(search):
			res = .9
		elif val.startswith(search):
			res = .9
		elif search in val.split(" "):
			res = .5
		elif search in val:
			res = .4

		return super(ResultRating, self).__new__(self, res)


class Episode(Base):

	__tablename__ = "episodes"
	show_id = Column(Integer, ForeignKey("shows.show_id"), primary_key=True)
	num = Column(Integer, primary_key=True)
	airdate = Column(Date)
	season = Column(Integer, primary_key=True)
	title = Column(Text)
	totalnum = Column(Integer)
	prodnum = Column(Text)

	def render(self, format):

		format = format.replace("##SHOW##", self.show.name)
		format = format.replace("##SEASON##", "%d" % self.season)
		format = format.replace("##SEASON2##", "%02d" % self.season)
		format = format.replace("##EPISODE##", "%02d" % self.num)
		format = format.replace("##TITLE##", "%s" % self.title)

		return format

	def __str__(self):

		return "%s S%02dE%02d: %s" % (self.show.name,
					self.season, self.num, self.title)


class Show(Base):

	__tablename__ = 'shows'
	id = Column('show_id', Integer, primary_key=True)
	name = Column('show_name', Text)
	url = Column(Text, unique=True)
	updated = Column(DateTime)
	enabled = Column(Boolean)
	status = Column(Integer)

	episodes = relationship(Episode, cascade="all,delete", backref="show")

	def __lt__(self, other):

		return self.name.__lt__(other.name)

	def __str__(self):

		return "Webisoder show '%s'" % self.name

	def __get_next_episode(self):

		today = date.today()
		episodes = self.episodes

		for ep in episodes:
			if not ep.airdate:
				continue

			if ep.airdate >= today:
				return ep

		return None

	next_episode = property(__get_next_episode)


class User(Base):

	__tablename__ = 'users'
	name = Column("user_name", String(30), primary_key=True)
	passwd = Column(String(64), nullable=False)
	mail = Column(String(50), unique=True, nullable=False)
	signup = Column(DateTime, nullable=False, default=datetime.now)
	verified = Column(Boolean, nullable=False, default=False)
	token = Column(String(12))
	days_back = Column(Numeric, nullable=False, default=7)
	link_format = Column(Text)
	site_news = Column(Boolean, nullable=False, default=True)
	latest_news_read = Column(DateTime)
	date_offset = Column(Integer)
	last_login = Column(DateTime)
	recover_key = Column(String(30))

	shows = relationship(Show, secondary=subscriptions, backref="users")

	def __set_password(self, plain):

		self.recover_key = None
		self.passwd = hashpw(plain.encode(), gensalt())

	def authenticate(self, password):

		try:

			digest = hashpw(password.encode(), self.passwd.encode())

			if digest == self.passwd:
				self.recover_key = None
				return True

		except ValueError:

			digest = md5(password.encode()).hexdigest()
			if digest == self.passwd:
				self.password = password
				self.recover_key = None
				return True

		return False

	def reset_token(self):

		self.token = ''.join(SystemRandom().choice(ascii_uppercase +
			ascii_lowercase + digits) for _ in range(12))

	def generate_password(self):

		password = ''.join(SystemRandom().choice(ascii_uppercase +
			ascii_lowercase + digits) for _ in range(12))
		self.password = password
		return password

	def generate_recover_key(self):

		key = ''.join(SystemRandom().choice(ascii_uppercase +
			ascii_lowercase + digits) for _ in range(30))
		self.recover_key = key

	def __get_episodes(self):

		shows = [x.id for x in self.shows]

		if not shows:
			return []

		matches = DBSession.query(Episode).filter(
						Episode.show_id.in_(shows))
		return [x for x in matches]

	episodes = property(__get_episodes)
	password = property(None, __set_password)


Index('user_index', User.name, unique=True)
Index('show_id', Show.id, unique=True)
