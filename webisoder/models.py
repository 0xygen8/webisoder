# webisoder
# Copyright (C) 2006-2015  Stefan Ott
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
from datetime import date

from sqlalchemy import Table, ForeignKey, Index
from sqlalchemy import Boolean, Column, Date, DateTime, Integer, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.orm import relationship, backref

from hashlib import md5, sha256

from zope.sqlalchemy import ZopeTransactionExtension

DBSession = scoped_session(sessionmaker(extension=ZopeTransactionExtension()))
Base = declarative_base()

subscriptions = Table('subscriptions', Base.metadata,
	Column('show_id', Integer, ForeignKey('shows.show_id')),
	Column('user_name', Text, ForeignKey('users.user_name')))

class User(Base):

	__tablename__ = 'users'
	name = Column('user_name', Text(30), primary_key=True)
	passwd = Column(Text(64))
	salt = Column(Text)
	mail = Column(Text(50), unique=True)
	signup = Column(DateTime)
	verified = Column(Boolean)
	token = Column(Text(12))
	days_back = Column(Integer)
	link_provider = Column(Text(20))
	link_format = Column(Text)
	site_news = Column(Boolean)
	lastest_news_read = Column(DateTime)
	date_offset = Column(Integer)
	last_login = Column(DateTime)

	def __set_password(self, plain):

		self.salt = ''.join(SystemRandom().choice(ascii_uppercase +
			ascii_lowercase + digits) for _ in range(10))
		self.passwd = sha256((self.salt + plain).encode()).hexdigest()

	def authenticate(self, password):

		digest = sha256((self.salt + password).encode()).hexdigest()

		if digest == self.passwd:
			return True

		digest = md5(password.encode()).hexdigest()
		if digest == self.passwd:
			self.password = password
			return True

		return False

	def reset_token(self):

		self.token = ''.join(SystemRandom().choice(ascii_uppercase +
			ascii_lowercase + digits) for _ in range(12))

	def __get_episodes(self):

		shows = [x.id for x in self.shows]

		if not shows:
			return []

		matches = DBSession.query(Episode).filter(
						Episode.show_id.in_(shows))
		return [x for x in matches]

	episodes = property(__get_episodes)
	password = property(None, __set_password)

class Show(Base):

	__tablename__ = 'shows'
	id = Column('show_id', Integer, primary_key=True)
	name = Column('show_name', Text)
	url = Column(Text)
	updated = Column(DateTime)
	enabled = Column(Boolean)
	status = Column(Integer)

	users = relationship(User, secondary=subscriptions, backref='shows')

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

class Episode(Base):

	__tablename__ = 'episodes'
	show_id = Column(Integer, ForeignKey('shows.show_id'), primary_key=True)
	num = Column(Integer, primary_key=True)
	airdate = Column(Date)
	season = Column(Integer, primary_key=True)
	title = Column(Text)
	totalnum = Column(Integer)
	prodnum = Column(Text)

	show = relationship(Show, backref='episodes')

	def render(self, format):

		format = format.replace('##SHOW##', self.show.name)
		format = format.replace('##SEASON##', "%d" % self.season)
		format = format.replace('##SEASON2##', "%02d" % self.season)
		format = format.replace('##EPISODE##', "%02d" % self.num)
		format = format.replace('##TITLE##', "%s" % self.title)

		return format

	def __str__(self):

		return '%s S%02dE%02d: %s' % (self.show.name,
					self.season, self.num, self.title)

Index('user_index', User.name, unique=True)
Index('show_id', Show.id, unique=True)
