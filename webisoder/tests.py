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

import unittest
import transaction
import re

from datetime import date, timedelta
from pyramid import testing
from pyramid_mailer import get_mailer
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.authentication import SessionAuthenticationPolicy
from pyramid.httpexceptions import HTTPBadRequest
from sqlalchemy import create_engine
from tvdb_api import tvdb_shownotfound

from deform.exception import ValidationFailure

from .models import DBSession
from .models import Base, Show, Episode, User

from .views import IndexController, RegistrationController, TokenResetController
from .views import ShowsController, EpisodesController, PasswordChangeController
from .views import ProfileController, AuthController, PasswordRecoveryController
from .views import FeedSettingsController, PasswordResetController
from .views import SearchController

from .errors import LoginFailure, DuplicateEmail, MailError, SubscriptionFailure
from .errors import DuplicateUserName, FormError

from .mail import WelcomeMessage, PasswordRecoveryMessage

import logging

log = logging.getLogger("webisoder.views")
log.addHandler(logging.NullHandler())


class Database(object):

	_engine = None

	@staticmethod
	def connect():

		if Database._engine:
			return

		Database._engine = create_engine("sqlite://")
		DBSession.configure(bind=Database._engine)
		Base.metadata.create_all(Database._engine)


class MockUser(object):

	@staticmethod
	def mockAuthentication():

		def setUnhashedPassword(self, plain):

			self.passwd = plain

		def authenticateUnhashed(self, password):

			return password == self.passwd

		User.origPassword = User.password
		User.origAuth = User.authenticate
		User.password = property(None, setUnhashedPassword)
		User.authenticate = authenticateUnhashed

	@staticmethod
	def resetAuthentication():

		User.password = User.origPassword
		User.authenticate = User.origAuth


class WebisoderTest(unittest.TestCase):

	def setUp(self):

		self.config = testing.setUp()
		Database.connect()

		authentication_policy = SessionAuthenticationPolicy()
		authorization_policy = ACLAuthorizationPolicy()
		self.config.set_authorization_policy(authorization_policy)
		self.config.set_authentication_policy(authentication_policy)

		self.config.add_route("profile", "__PROFILE__")
		self.config.add_route("settings_token", "__TOKEN__")
		self.config.add_route("settings_pw", "__PW__")
		self.config.add_route("settings_feed", "__FEED__")
		self.config.add_route("shows", "__SHOWS__")
		self.config.add_route("login", "__LOGIN__")
		self.config.add_route("recover", "__RECOVER__")
		self.config.add_route("reset_password", "__REC__/{key}")


class WebisoderModelTests(unittest.TestCase):

	def setUp(self):

		super(WebisoderModelTests, self).setUp()
		self.config = testing.setUp()
		Database.connect()

		with transaction.manager:

			show1 = Show(id=1, name='show1', url='http://1')
			show2 = Show(id=2, name='show2', url='http://2')

			DBSession.add(show1)
			DBSession.add(show2)

			DBSession.add(Episode(show=show1, num=1, season=1))
			DBSession.add(Episode(show=show1, num=2, season=1))
			DBSession.add(Episode(show=show2, num=1, season=1))

			DBSession.add(User(name='user1'))
			DBSession.add(User(name='user2'))
			DBSession.add(User(name='user3'))

	def tearDown(self):

		with transaction.manager:

			DBSession.query(Episode).delete()
			DBSession.query(Show).delete()
			DBSession.query(User).delete()

		DBSession.remove()
		testing.tearDown()

	def testUserToken(self):

		user1 = DBSession.query(User).get('user1')
		user1.token = 'token'

		user1.reset_token()
		token = user1.token
		self.assertNotEqual(token, 'token')
		self.assertEqual(12, len(token))

		user1.reset_token()
		self.assertNotEqual(token, user1.token)
		self.assertEqual(12, len(token))

	def testShowEpisodeRelation(self):

		show1 = DBSession.query(Show).get(1)
		show2 = DBSession.query(Show).get(2)

		s1e1 = DBSession.query(Episode).filter_by(
				show=show1, num=1, season=1).first()
		s1e2 = DBSession.query(Episode).filter_by(
				show=show1, num=2, season=1).first()
		s2e1 = DBSession.query(Episode).filter_by(
				show=show2, num=1, season=1).first()

		self.assertNotEqual(s1e1, s1e2)

		self.assertEqual(2, len(show1.episodes))
		self.assertIn(s1e1, show1.episodes)
		self.assertIn(s1e2, show1.episodes)

		self.assertEqual(1, len(show2.episodes))
		self.assertIn(s2e1, show2.episodes)

		self.assertEqual(s1e1.show, show1)
		self.assertEqual(s1e2.show, show1)
		self.assertEqual(s2e1.show, show2)

	def testSubscriptions(self):

		user1 = DBSession.query(User).get('user1')
		user2 = DBSession.query(User).get('user2')
		user3 = DBSession.query(User).get('user3')

		show1 = DBSession.query(Show).get(1)
		show2 = DBSession.query(Show).get(2)

		self.assertEqual(0, len(user1.shows))
		self.assertEqual(0, len(user2.shows))
		self.assertEqual(0, len(user3.shows))

		user2.shows.append(show1)
		user3.shows.append(show1)
		user3.shows.append(show2)

		user1 = DBSession.query(User).get('user1')
		user2 = DBSession.query(User).get('user2')
		user3 = DBSession.query(User).get('user3')

		self.assertEqual(0, len(user1.shows))
		self.assertEqual(1, len(user2.shows))
		self.assertEqual(2, len(user3.shows))

		self.assertIn(show1, user2.shows)
		self.assertIn(show1, user3.shows)
		self.assertIn(show2, user3.shows)

		self.assertNotIn(user1, show1.users)
		self.assertIn(user2, show1.users)
		self.assertIn(user3, show1.users)

		self.assertNotIn(user1, show2.users)
		self.assertNotIn(user2, show2.users)
		self.assertIn(user3, show2.users)

	def testUserEpisodes(self):

		user1 = DBSession.query(User).get('user1')
		user2 = DBSession.query(User).get('user2')
		user3 = DBSession.query(User).get('user3')

		show1 = DBSession.query(Show).get(1)
		show2 = DBSession.query(Show).get(2)

		user2.shows.append(show1)
		user3.shows.append(show1)
		user3.shows.append(show2)

		s1e1 = DBSession.query(Episode).filter_by(
				show=show1, num=1, season=1).first()
		s1e2 = DBSession.query(Episode).filter_by(
				show=show1, num=2, season=1).first()
		s2e1 = DBSession.query(Episode).filter_by(
				show=show2, num=1, season=1).first()

		self.assertEqual(0, len(user1.episodes))
		self.assertEqual(2, len(user2.episodes))
		self.assertEqual(3, len(user3.episodes))

		self.assertIn(s1e1, user2.episodes)
		self.assertIn(s1e2, user2.episodes)

		self.assertIn(s1e1, user3.episodes)
		self.assertIn(s1e2, user3.episodes)
		self.assertIn(s2e1, user3.episodes)

		user3.shows.remove(show1)
		self.assertEqual(1, len(user3.episodes))

	def testAuthentication(self):

		user = DBSession.query(User).get('user1')
		user.salt = ''
		user.password = 'letmein'

		self.assertTrue(user.authenticate('letmein'))

	def testGeneratePassword(self):

		user = DBSession.query(User).get('user1')
		password = user.generate_password()

		self.assertEqual(12, len(password))
		self.assertTrue(user.authenticate(password))

	def testGenerateRecoverKey(self):

		user = DBSession.query(User).get('user1')
		self.assertEqual(None, user.recover_key)
		user.generate_recover_key()

		self.assertNotEqual(None, user.recover_key)
		self.assertEqual(30, len(user.recover_key))

	def testUpgradePassword(self):

		user = DBSession.query(User).get('user1')
		user.passwd = '0d107d09f5bbe40cade3de5c71e9e9b7'
		user.salt = ''

		self.assertEqual('0d107d09f5bbe40cade3de5c71e9e9b7',
								user.passwd)
		self.assertEqual('', user.salt)

		self.assertTrue(user.authenticate('letmein'))
		self.assertNotEqual('0d107d09f5bbe40cade3de5c71e9e9b7',
								user.passwd)

		self.assertTrue(user.authenticate('letmein'))

	def testLoginRemovesResetToken(self):

		user = DBSession.query(User).get("user1")
		user.password = "first"
		user.recover_key = "testkey287"

		user = DBSession.query(User).get("user1")
		self.assertEqual("testkey287", user.recover_key)
		user.authenticate("wrong")

		user = DBSession.query(User).get("user1")
		self.assertEqual("testkey287", user.recover_key)
		user.authenticate("first")

		user = DBSession.query(User).get("user1")
		self.assertEqual(None, user.recover_key)

		user = DBSession.query(User).get("user1")
		user.passwd = "0d107d09f5bbe40cade3de5c71e9e9b7"
		user.recover_key = "testkey302"
		user.authenticate("wrong")

		user = DBSession.query(User).get("user1")
		self.assertEqual("testkey302", user.recover_key)
		user.authenticate("letmein")

		user = DBSession.query(User).get("user1")
		self.assertEqual(None, user.recover_key)

	def testPasswordUpdateRemovesResetToken(self):

		user = DBSession.query(User).get("user1")
		user.recover_key = "testkey315"

		self.assertEqual("testkey315", user.recover_key)
		user.password = "something"
		self.assertEqual(None, user.recover_key)

	def testRenderEpisode(self):

		show = DBSession.query(Show).get(1)

		ep = Episode(show=show, num=12, season=5, title="test me")
		fmt = '//##SHOW## ##SEASON##x##EPISODE##'
		self.assertEqual('//show1 5x12', ep.render(fmt))

		ep = Episode(show=show, num=2, season=5, title="test me")
		fmt = '//##SHOW## S##SEASON2##E##EPISODE##'
		self.assertEqual('//show1 S05E02', ep.render(fmt))

		ep = Episode(show=show, num=102, season=1, title="test me")
		fmt = '//##SHOW## S##SEASON2##E##EPISODE##'
		self.assertEqual('//show1 S01E102', ep.render(fmt))

		ep = Episode(show=show, num=102, season=1, title="test me")
		fmt = '//##SHOW## : ##TITLE##'
		self.assertEqual('//show1 : test me', ep.render(fmt))

	def testNextEpisode(self):

		show = DBSession.query(Show).get(2)
		today = date.today()

		ep1 = Episode(show=show, num=1, season=1, title="1")
		ep2 = Episode(show=show, num=2, season=1, title="2")
		ep3 = Episode(show=show, num=3, season=1, title="3")

		ep1.airdate = today - timedelta(1)
		ep2.airdate = today + timedelta(1)
		ep3.airdate = today + timedelta(2)

		DBSession.add(ep1)
		DBSession.add(ep2)
		DBSession.add(ep3)

		with DBSession.no_autoflush:
			ep = show.next_episode

		self.assertEqual(ep, ep2)


class TestNewUserSignup(WebisoderTest):

	def setUp(self):

		super(TestNewUserSignup, self).setUp()
		MockUser.mockAuthentication()

		self.config.include("pyramid_chameleon")
		self.config.include('pyramid_mailer.testing')

	def tearDown(self):

		with transaction.manager:

			DBSession.query(User).delete()

		MockUser.resetAuthentication()
		testing.tearDown()

	def testSignup(self):

		request = testing.DummyRequest(post={
			"name": "newuser1",
			"email": "newuser1@example.org"
		})

		mailer = get_mailer(request)
		self.assertEqual(len(mailer.outbox), 0)
		ctl = RegistrationController(request)
		ctl.post()
		self.assertEqual(len(mailer.outbox), 1)

		message = mailer.outbox[0]
		self.assertEqual(message.subject, "New user registration")
		self.assertEqual(message.sender, "noreply@webisoder.net")
		self.assertEqual(len(message.recipients), 1)
		self.assertIn("newuser1@example.org", message.recipients)
		self.assertIn("newuser1", message.body)
		self.assertIn("your initial password is", message.body)

		msg = request.session.pop_flash("info")
		self.assertEqual(1, len(msg))

		matches = re.findall("[a-zA-Z0-9]{12}", message.body)
		self.assertEqual(len(matches), 1)
		password = matches[0]

		user = DBSession.query(User).get("newuser1")
		self.assertTrue(user.authenticate(password))
		self.assertEqual(user.mail, "newuser1@example.org")

	def testInvalidSignupForm(self):

		# No e-mail address
		request = testing.DummyRequest(post={"name": "newuser3"})
		ctl = RegistrationController(request)

		with self.assertRaises(ValidationFailure) as ctx:
			ctl.post()

		mailer = get_mailer(request)
		self.assertEqual(len(mailer.outbox), 0)

		request.exception = ctx.exception
		res = ctl.failure()

		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertIn("email", errors)
		self.assertEqual("Required", errors.get("email"))
		self.assertNotIn("name", errors)

		# No user name, invalid e-mail address
		request = testing.DummyRequest(post={"email": "newuser3"})
		ctl = RegistrationController(request)

		with self.assertRaises(ValidationFailure) as ctx:
			ctl.post()

		mailer = get_mailer(request)
		self.assertEqual(len(mailer.outbox), 0)

		request.exception = ctx.exception
		res = ctl.failure()

		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertIn("email", errors)
		self.assertEqual("Invalid email address", errors.get("email"))
		self.assertIn("name", errors)
		self.assertEqual("Required", errors.get("name"))

	def testInvalidMailAddress(self):

		# Invalid address
		request = testing.DummyRequest(post={
			"name": "newuser4",
			"email": "newuser1"
		})
		ctl = RegistrationController(request)

		with self.assertRaises(ValidationFailure) as ctx:
			ctl.post()

		mailer = get_mailer(request)
		self.assertEqual(len(mailer.outbox), 0)

		request.exception = ctx.exception
		res = ctl.failure()

		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual("Invalid email address", errors.get("email"))
		self.assertNotIn("name", errors)

		# Empty address
		request = testing.DummyRequest(post={
			"name": "newuser4",
			"email": ""
		})
		mailer = get_mailer(request)
		ctl = RegistrationController(request)

		with self.assertRaises(ValidationFailure) as ctx:
			ctl.post()

		mailer = get_mailer(request)
		self.assertEqual(len(mailer.outbox), 0)

		request.exception = ctx.exception
		res = ctl.failure()

		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual("Required", errors.get("email"))
		self.assertNotIn("name", errors)

		# Another invalid address
		request = testing.DummyRequest(post={
			"name": "newuser4",
			"email": "@example.org"
		})
		ctl = RegistrationController(request)

		with self.assertRaises(ValidationFailure) as ctx:
			ctl.post()

		mailer = get_mailer(request)
		self.assertEqual(len(mailer.outbox), 0)

		request.exception = ctx.exception
		res = ctl.failure()

		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual("Invalid email address", errors.get("email"))
		self.assertNotIn("name", errors)

	def testInvalidUserName(self):

		# No user name
		request = testing.DummyRequest(post={
			"email": "newuser1@example.org"
		})
		ctl = RegistrationController(request)

		with self.assertRaises(ValidationFailure) as ctx:
			ctl.post()

		mailer = get_mailer(request)
		self.assertEqual(len(mailer.outbox), 0)

		request.exception = ctx.exception
		res = ctl.failure()

		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual("Required", errors.get("name"))
		self.assertNotIn("email", errors)

		# Empty user name
		request = testing.DummyRequest(post={
			"name": "",
			"email": "newuser2@example.org"
		})
		mailer = get_mailer(request)
		ctl = RegistrationController(request)

		with self.assertRaises(ValidationFailure) as ctx:
			ctl.post()

		mailer = get_mailer(request)
		self.assertEqual(len(mailer.outbox), 0)

		request.exception = ctx.exception
		res = ctl.failure()

		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual("Required", errors.get("name"))
		self.assertNotIn("email", errors)

	def testDuplicateUserName(self):

		request = testing.DummyRequest(post={
			"name": "newuserX",
			"email": "newuserX@example.org"
		})
		mailer = get_mailer(request)
		ctl = RegistrationController(request)
		res = ctl.post()
		self.assertNotIn("form_errors", res)
		self.assertEqual(len(mailer.outbox), 1)

		request = testing.DummyRequest(post={
			"name": "newuserX",
			"email": "newuserX1@example.org"
		})
		mailer = get_mailer(request)
		ctl = RegistrationController(request)

		with self.assertRaises(DuplicateUserName) as ctx:
			ctl.post()

		self.assertEqual(len(mailer.outbox), 1)

		request.exception = ctx.exception
		res = ctl.failure()

		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual("This name is already taken", errors.get("name"))
		self.assertNotIn("email", errors)
		self.assertEqual(res.get("name"), "newuserX")
		self.assertEqual(res.get("email"), "newuserX1@example.org")

	def testDuplicateEmail(self):

		request = testing.DummyRequest(post={
			"name": "newuserX",
			"email": "newuserX@example.org"
		})
		mailer = get_mailer(request)
		ctl = RegistrationController(request)
		res = ctl.post()
		self.assertNotIn("form_errors", res)
		self.assertEqual(len(mailer.outbox), 1)

		request = testing.DummyRequest(post={
			"name": "newuserY",
			"email": "newuserX@example.org"
		})
		mailer = get_mailer(request)
		ctl = RegistrationController(request)

		with self.assertRaises(DuplicateEmail) as ctx:
			ctl.post()

		self.assertEqual(len(mailer.outbox), 1)

		request.exception = ctx.exception
		res = ctl.failure()

		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual("This e-mail address is already in use",
							errors.get("email"))
		self.assertNotIn("name", errors)
		self.assertEqual(res.get("name"), "newuserY")
		self.assertEqual(res.get("email"), "newuserX@example.org")


class TestRecoverPassword(WebisoderTest):

	def setUp(self):

		super(TestRecoverPassword, self).setUp()
		MockUser.mockAuthentication()

		self.config.include('pyramid_mailer.testing')
		self.config.include('pyramid_chameleon')

		with transaction.manager:

			user = User(name="testuser467")
			user.password = "secret"
			user.mail = "user@example.com"
			DBSession.add(user)

	def tearDown(self):

		with transaction.manager:

			user = DBSession.query(User).get("testuser467")
			for show in user.shows:
				user.shows.remove(show)
			DBSession.delete(user)

		MockUser.resetAuthentication()
		testing.tearDown()

	def testRequestPasswordWithoutEmailAddress(self):

		request = testing.DummyRequest(post={ })
		ctl = PasswordRecoveryController(request)

		with self.assertRaises(ValidationFailure) as ctx:
			ctl.post()

		mailer = get_mailer(request)
		self.assertEqual(len(mailer.outbox), 0)

		request.exception = ctx.exception
		res = ctl.failure()

		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual("Required", errors.get("email"))

	def testRequestPasswordForEmptyEmailAddress(self):

		request = testing.DummyRequest(post={"email": ""})
		ctl = PasswordRecoveryController(request)

		with self.assertRaises(ValidationFailure) as ctx:
			ctl.post()

		mailer = get_mailer(request)
		self.assertEqual(len(mailer.outbox), 0)

		request.exception = ctx.exception
		res = ctl.failure()

		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual("Required", errors.get("email"))

	def testRequestPasswordForInvalidEmailAddress(self):

		request = testing.DummyRequest(post={
			"email": "user.example.com"
		})
		ctl = PasswordRecoveryController(request)

		with self.assertRaises(ValidationFailure) as ctx:
			ctl.post()

		mailer = get_mailer(request)
		self.assertEqual(len(mailer.outbox), 0)

		request.exception = ctx.exception
		res = ctl.failure()

		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual("Invalid email address", errors.get("email"))

	def testRequestPasswordForInvalidUser(self):

		request = testing.DummyRequest(post={
			"email": "nosuchuser@example.com"
		})

		ctl = PasswordRecoveryController(request)
		with self.assertRaises(FormError) as ctx:
			ctl.post()

		mailer = get_mailer(request)
		self.assertEqual(len(mailer.outbox), 0)

		request.exception = ctx.exception
		res = ctl.failure()

		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual("No such user", errors.get("email"))
		self.assertEqual(res.get("email"), "nosuchuser@example.com")

	def testRequestPassword(self):

		request = testing.DummyRequest(post={
			"email": "user@example.com"
		})
		mailer = get_mailer(request)
		ctl = PasswordRecoveryController(request)

		self.assertEqual(len(mailer.outbox), 0)
		res = ctl.post()

		self.assertNotIn("form_errors", res)
		self.assertTrue(hasattr(res, "location"))
		self.assertTrue(res.location.endswith("__LOGIN__"))
		self.assertEqual(len(mailer.outbox), 1)

		message = mailer.outbox[0]
		self.assertEqual(message.subject, "Webisoder password recovery")
		self.assertEqual(message.sender, 'noreply@webisoder.net')
		self.assertEqual(len(message.recipients), 1)
		self.assertIn("user@example.com", message.recipients)
		self.assertIn("testuser467", message.body)
		self.assertIn("To reset your password", message.body)
		self.assertNotIn("__RECOVER__", message.body)
		self.assertIn("__REC__", message.body)
		self.assertIn("__LOGIN__", message.body)

		user = DBSession.query(User).get("testuser467")
		self.assertEqual(user.name, "testuser467")
		self.assertNotEqual(user.recover_key, None)
		self.assertNotEqual(user.recover_key, "")
		self.assertEqual(len(user.recover_key), 30)
		self.assertIn(user.recover_key, message.body)

	def testGetResetForm(self):

		request = testing.DummyRequest()
		ctl = PasswordResetController(request)

		with self.assertRaises(HTTPBadRequest):
			ctl.get()

		request = testing.DummyRequest()
		request.matchdict["key"] = ""
		ctl = PasswordResetController(request)

		with self.assertRaises(HTTPBadRequest):
			ctl.get()

		request = testing.DummyRequest()
		request.matchdict["key"] = "testkey615"
		ctl = PasswordResetController(request)
		res = ctl.get()
		self.assertIn("key", res)
		self.assertEqual(res.get("key"), "testkey615")

	def testPostWrongResetForm(self):

		# Missing e-mail address
		request = testing.DummyRequest(post={
			"password": "newpwd",
			"verify": "newpwd"
		})
		request.matchdict["key"] = "testkey639"
		ctl = PasswordResetController(request)

		with self.assertRaises(ValidationFailure) as ctx:
			ctl.post()

		request.exception = ctx.exception
		res = ctl.failure()

		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual("Required", errors.get("email"))
		self.assertEqual(res.get("email"), None)
		self.assertEqual(res.get("key"), "testkey639")

		# Missing password
		request = testing.DummyRequest(post={
			"email": "user@example.com",
			"verify": "newpwd"
		})
		request.matchdict["key"] = "testkey639"
		ctl = PasswordResetController(request)

		with self.assertRaises(ValidationFailure) as ctx:
			ctl.post()

		request.exception = ctx.exception
		res = ctl.failure()

		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual("Required", errors.get("password"))
		self.assertEqual(res.get("email"), "user@example.com")
		self.assertEqual(res.get("key"), "testkey639")

		# Missing password verification
		request = testing.DummyRequest(post={
			"email": "user@example.com",
			"password": "newpwd"
		})
		request.matchdict["key"] = "testkey639"
		ctl = PasswordResetController(request)

		with self.assertRaises(ValidationFailure) as ctx:
			ctl.post()

		request.exception = ctx.exception
		res = ctl.failure()

		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual("Required", errors.get("verify"))
		self.assertEqual(res.get("email"), "user@example.com")
		self.assertEqual(res.get("key"), "testkey639")

		# Password too short
		request = testing.DummyRequest(post={
			"email": "user@example.com",
			"password": "newpw",
			"verify": "newpw"
		})
		request.matchdict["key"] = "testkey639"
		ctl = PasswordResetController(request)

		with self.assertRaises(ValidationFailure) as ctx:
			ctl.post()

		request.exception = ctx.exception
		res = ctl.failure()

		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual("Shorter than minimum length 6",
							errors.get("password"))
		self.assertEqual(res.get("email"), "user@example.com")
		self.assertEqual(res.get("key"), "testkey639")

		# Wrong password verification
		request = testing.DummyRequest(post={
			"email": "user@example.com",
			"password": "newpwd",
			"verify": "newpw"
		})
		request.matchdict["key"] = "testkey639"
		ctl = PasswordResetController(request)

		with self.assertRaises(FormError) as ctx:
			ctl.post()

		request.exception = ctx.exception
		res = ctl.failure()

		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual("Passwords do not match", errors.get("verify"))
		self.assertEqual(res.get("email"), "user@example.com")
		self.assertEqual(res.get("key"), "testkey639")

		# Invalid e-mail address
		request = testing.DummyRequest(post={
			"email": "user.example.com",
			"password": "newpwd",
			"verify": "newpwd"
		})
		request.matchdict["key"] = "testkey639"
		ctl = PasswordResetController(request)

		with self.assertRaises(ValidationFailure) as ctx:
			ctl.post()

		request.exception = ctx.exception
		res = ctl.failure()

		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual("Invalid email address", errors.get("email"))
		self.assertEqual(res.get("email"), "user.example.com")
		self.assertEqual(res.get("key"), "testkey639")

		# Invalid user
		request = testing.DummyRequest(post={
			"email": "nosuchuser@example.com",
			"password": "newpwx",
			"verify": "newpwx"
		})
		request.matchdict["key"] = "testkey639"
		ctl = PasswordResetController(request)

		with self.assertRaises(FormError) as ctx:
			ctl.post()

		request.exception = ctx.exception
		res = ctl.failure()

		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual("No such user", errors.get("email"))
		self.assertEqual(res.get("email"), "nosuchuser@example.com")
		self.assertEqual(res.get("key"), "testkey639")

		# No recovery key
		request = testing.DummyRequest(post={
			"email": "user@example.com",
			"password": "newpwd",
			"verify": "newpwd"
		})
		ctl = PasswordResetController(request)

		with self.assertRaises(FormError) as ctx:
			ctl.post()

		request.exception = ctx.exception
		res = ctl.failure()

		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual("Wrong recovery key", errors.get("key"))
		self.assertEqual(res.get("email"), "user@example.com")
		self.assertEqual(res.get("key"), None)

		# Wrong recovery key
		request = testing.DummyRequest(post={
			"email": "user@example.com",
			"password": "newpwx",
			"verify": "newpwx"
		})
		request.matchdict["key"] = "wrongkey"
		ctl = PasswordResetController(request)

		with self.assertRaises(FormError) as ctx:
			ctl.post()

		request.exception = ctx.exception
		res = ctl.failure()

		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual("Wrong recovery key", errors.get("key"))
		self.assertEqual(res.get("email"), "user@example.com")
		self.assertEqual(res.get("key"), "wrongkey")

	def testPostResetForm(self):

		user = DBSession.query(User).get("testuser467")
		user.recover_key = "testkey639"

		request = testing.DummyRequest(post={
			"email": "user@example.com",
			"password": "newpwx",
			"verify": "newpwx"
		})
		request.matchdict["key"] = "testkey639"
		ctl = PasswordResetController(request)

		user = DBSession.query(User).get("testuser467")
		self.assertEqual("testkey639", user.recover_key)
		res = ctl.post()

		self.assertNotIn("form_errors", res)
		self.assertTrue(user.authenticate("newpwx"))

		self.assertTrue(hasattr(res, "location"))
		self.assertTrue(res.location.endswith("__LOGIN__"))


class TestAuthenticationAndAuthorization(WebisoderTest):

	def setUp(self):

		super(TestAuthenticationAndAuthorization, self).setUp()
		MockUser.mockAuthentication()

		self.config.add_route("shows", "__SHOWS__")
		self.config.add_route("home", "__HOME__")

		with transaction.manager:

			user = User(name="testuser100")
			user.password = "secret"
			DBSession.add(user)

	def tearDown(self):

		with transaction.manager:

			user = DBSession.query(User).get("testuser100")
			for s in user.shows:
				user.unsubscribe(s)
			DBSession.delete(user)

		MockUser.resetAuthentication()

		DBSession.remove()
		testing.tearDown()

	def testInvalidUserName(self):

		request = testing.DummyRequest(post={
			"user": "testuser2",
			"password": "secret"
		})

		view = AuthController(request)

		with self.assertRaises(LoginFailure):
			view.login_post()

		self.assertNotIn("auth.userid", request.session)

		res = view.failure()
		self.assertFalse(hasattr(res, "location"))
		self.assertEqual("testuser2", res.get("user"))
		self.assertEqual("secret", res.get("password"))

		msg = request.session.pop_flash("warning")
		self.assertEqual(1, len(msg))
		self.assertEqual("Login failed", msg[0])

	def testEmptyUserName(self):

		request = testing.DummyRequest(post={
			"user": "",
			"password": "wrong"
		})

		view = AuthController(request)

		with self.assertRaises(ValidationFailure):
			view.login_post()

		self.assertNotIn("auth.userid", request.session)

		res = view.failure()
		self.assertFalse(hasattr(res, "location"))
		self.assertEqual("", res.get("user"))
		self.assertEqual("wrong", res.get("password"))

		msg = request.session.pop_flash("warning")
		self.assertEqual(1, len(msg))
		self.assertEqual("Login failed", msg[0])

	def testMissingUserName(self):

		request = testing.DummyRequest(post={
			"password": "wrong"
		})

		view = AuthController(request)

		with self.assertRaises(ValidationFailure):
			view.login_post()

		self.assertNotIn("auth.userid", request.session)

		res = view.failure()
		self.assertFalse(hasattr(res, "location"))
		self.assertEqual("wrong", res.get("password"))

		msg = request.session.pop_flash("warning")
		self.assertEqual(1, len(msg))
		self.assertEqual("Login failed", msg[0])


	def testInvalidPassword(self):

		request = testing.DummyRequest(post={
			"user": "testuser100",
			"password": "wrong"
		})

		view = AuthController(request)

		with self.assertRaises(LoginFailure):
			view.login_post()

		self.assertNotIn("auth.userid", request.session)

		res = view.failure()
		self.assertFalse(hasattr(res, "location"))
		self.assertEqual("testuser100", res.get("user"))

		msg = request.session.pop_flash("warning")
		self.assertEqual(1, len(msg))
		self.assertEqual("Login failed", msg[0])

	def testEmptyPassword(self):

		request = testing.DummyRequest(post={
			"user": "testuser100",
			"password": ""
		})

		view = AuthController(request)

		with self.assertRaises(ValidationFailure):
			view.login_post()

		self.assertNotIn("auth.userid", request.session)

		res = view.failure()
		self.assertFalse(hasattr(res, "location"))
		self.assertEqual("testuser100", res.get("user"))
		self.assertEqual("", res.get("password"))

		msg = request.session.pop_flash("warning")
		self.assertEqual(1, len(msg))
		self.assertEqual("Login failed", msg[0])

	def testMissingPassword(self):

		request = testing.DummyRequest(post={
			"user": "testuser100"
		})

		view = AuthController(request)

		with self.assertRaises(ValidationFailure):
			view.login_post()

		self.assertNotIn("auth.userid", request.session)

		res = view.failure()
		self.assertFalse(hasattr(res, "location"))
		self.assertEqual("testuser100", res.get("user"))

		msg = request.session.pop_flash("warning")
		self.assertEqual(1, len(msg))
		self.assertEqual("Login failed", msg[0])

	def testLoginLogout(self):

		request = testing.DummyRequest(post={
			"user": "testuser100",
			"password": "secret"
		})

		view = AuthController(request)
		res = view.login_post()

		self.assertTrue(hasattr(res, "location"))
		self.assertTrue(res.location.endswith("__SHOWS__"))

		self.assertIn("auth.userid", request.session)
		self.assertEqual("testuser100", request.session["auth.userid"])

		msg = request.session.pop_flash("warning")
		self.assertEqual(0, len(msg))

		msg = request.session.pop_flash("info")
		self.assertEqual(0, len(msg))

		res = view.logout()
		self.assertTrue(hasattr(res, "location"))
		self.assertTrue(res.location.endswith("__HOME__"))
		self.assertNotIn("auth.userid", request.session)

		msg = request.session.pop_flash("info")
		self.assertEqual(1, len(msg))
		self.assertEqual("Successfully signed out. Goodbye.", msg[0])


class TestShowsView(WebisoderTest):

	def setUp(self):

		super(TestShowsView, self).setUp()
		MockUser.mockAuthentication()

		with transaction.manager:

			self.user = User(name='testuser1')
			self.user.password = "secret"
			self.user.token = 'mytoken'
			self.user.days_back = 0
			DBSession.add(self.user)

			self.show1 = Show(id=1, name='show1', url='http://1')
			self.show2 = Show(id=2, name='show2', url='http://2')
			self.show3 = Show(id=3, name='show3', url='http://3')
			self.show4 = Show(id=4, name='show4', url='http://4')

			self.user.shows.append(self.show1)
			self.user.shows.append(self.show2)
			self.user.shows.append(self.show3)

			today = date.today()

			ep1 = Episode(show=self.show2, num=1, season=1, title='ep1')
			ep2 = Episode(show=self.show2, num=2, season=1, title='ep2')
			ep3 = Episode(show=self.show1, num=1, season=1, title='ep3')
			ep4 = Episode(show=self.show1, num=2, season=1, title='ep4')
			ep5 = Episode(show=self.show1, num=3, season=1, title='ep5')

			ep1.airdate = today - timedelta(7)
			ep2.airdate = today + timedelta(7)
			ep3.airdate = today - timedelta(7)
			ep4.airdate = today - timedelta(2)
			ep5.airdate = today

			DBSession.add(ep1)
			DBSession.add(ep2)
			DBSession.add(ep3)
			DBSession.add(ep4)
			DBSession.add(ep5)

			DBSession.add(self.show4)

	def tearDown(self):

		with transaction.manager:

			user = DBSession.query(User).get("testuser1")
			shows = [s.id for s in user.shows]

			for id in shows:
				show = DBSession.query(Show).get(id)
				user.shows.remove(show)

			DBSession.query(Episode).delete()
			DBSession.query(Show).delete()
			DBSession.delete(user)

		MockUser.resetAuthentication()

		DBSession.remove()
		testing.tearDown()

	def testShowList(self):

		request = testing.DummyRequest()
		request.session["auth.userid"] = "testuser1"
		ctl = ShowsController(request)
		res = ctl.get()

		result_shows = [x.id for x in res["subscribed"]]
		self.assertIn(1, result_shows)
		self.assertIn(2, result_shows)
		self.assertIn(3, result_shows)
		self.assertNotIn(4, result_shows)

	def testSubscribeShow(self):

		request = testing.DummyRequest()
		request.session["auth.userid"] = "testuser1"
		ctl = ShowsController(request)
		with self.assertRaises(ValidationFailure):
			ctl.subscribe()

		request = testing.DummyRequest(post={"show": "a"})
		request.session["auth.userid"] = "testuser1"
		with self.assertRaises(ValidationFailure):
			ctl.subscribe()

		request = testing.DummyRequest(post={"show": "5"})
		request.session["auth.userid"] = "testuser1"
		ctl = ShowsController(request)
		with self.assertRaises(SubscriptionFailure):
			ctl.subscribe()

		request = testing.DummyRequest(post={"show": "4"})
		request.session["auth.userid"] = "testuser1"
		ctl = ShowsController(request)
		res = ctl.subscribe()
		self.assertTrue(hasattr(res, "location"))
		self.assertTrue(res.location.endswith("__SHOWS__"))

		msg = request.session.pop_flash("info")
		self.assertEqual(1, len(msg))
		self.assertEqual('Subscribed to "show4"', msg[0])

		ctl = ShowsController(request)
		res = ctl.get()

		result_shows = [x.id for x in res["subscribed"]]
		self.assertIn(1, result_shows)
		self.assertIn(2, result_shows)
		self.assertIn(3, result_shows)
		self.assertIn(4, result_shows)

	def testUnsubscribeShow(self):

		request = testing.DummyRequest()
		request.session["auth.userid"] = "testuser1"
		ctl = ShowsController(request)
		with self.assertRaises(ValidationFailure):
			ctl.unsubscribe()

		request = testing.DummyRequest(post={"show": "a"})
		request.session["auth.userid"] = "testuser1"
		ctl = ShowsController(request)
		with self.assertRaises(ValidationFailure):
			ctl.unsubscribe()

		request = testing.DummyRequest(post={"show": "5"})
		request.session["auth.userid"] = "testuser1"
		ctl = ShowsController(request)
		with self.assertRaises(SubscriptionFailure):
			ctl.unsubscribe()

		request = testing.DummyRequest(post={"show": "3"})
		request.session["auth.userid"] = "testuser1"
		ctl = ShowsController(request)
		res = ctl.unsubscribe()
		self.assertTrue(hasattr(res, "location"))
		self.assertTrue(res.location.endswith("__SHOWS__"))

		msg = request.session.pop_flash("info")
		self.assertEqual(1, len(msg))
		self.assertEqual('Unsubscribed from "show3"', msg[0])

		ctl = ShowsController(request)
		res = ctl.get()

		result_shows = [x.id for x in res["subscribed"]]
		self.assertIn(1, result_shows)
		self.assertIn(2, result_shows)
		self.assertNotIn(3, result_shows)
		self.assertNotIn(4, result_shows)

	def testSearch(self):

		class mock_show(object):

			def __init__(self, id):
				self.attr = {}
				self.attr["id"] = id

			def get(self, attr):
				return self.attr.get(attr)

		class tvdb_mock():

			def __init__(self, custom_ui=None):
				self.items = {
					"big bang theory": [ mock_show(80379) ],
					"doctor who": [
						mock_show(1),
						mock_show(2),
						mock_show(3),
						mock_show(4),
						mock_show(5),
						mock_show(6)
					]
				}
				self.ui = custom_ui(None)

			def __getitem__(self, item):

				if item in self.items:
					self.ui.selectSeries(self.items[item])
				else:
					raise tvdb_shownotfound()

		# No search term
		request = testing.DummyRequest(post={})
		request.session["auth.userid"] = "testuser1"
		ctl = SearchController(request)

		with self.assertRaises(ValidationFailure) as ctx:
			ctl.post(tvdb=tvdb_mock)

		request.exception = ctx.exception
		res = ctl.failure()

		self.assertIn("form_errors", res)
		errors = res.get("form_errors")
		self.assertEqual("Required", errors.get("search"))

		# Search term that exists
		request = testing.DummyRequest(post={
			"search": "big bang theory"
		})
		request.session["auth.userid"] = "testuser1"
		ctl = SearchController(request)
		res = ctl.post(tvdb=tvdb_mock)
		self.assertEqual(len(res.get("shows")), 1)
		self.assertEqual(res.get("search"), "big bang theory")
		show = res.get("shows")[0]
		self.assertEqual(show.get("id"), 80379)
		self.assertNotIn("form_errors", res)
		self.assertEqual(res.get("search"), "big bang theory")

		# Search term that does not exist
		request = testing.DummyRequest(post={
			"search": "this does not exist"
		})
		request.session["auth.userid"] = "testuser1"
		ctl = SearchController(request)

		with self.assertRaises(tvdb_shownotfound) as ctx:
			ctl.post(tvdb=tvdb_mock)

		request.exception = ctx.exception
		res = ctl.not_found()

		self.assertEqual(len(res.get("shows")), 0)
		self.assertNotIn("form_errors", res)
		self.assertEqual(res.get("search"), "this does not exist")

		# Search with lots of hits
		request = testing.DummyRequest(post={"search": "doctor who"})
		request.session["auth.userid"] = "testuser1"
		ctl = SearchController(request)
		res = ctl.post(tvdb=tvdb_mock)
		self.assertTrue(len(res.get("shows")) > 5)
		self.assertNotIn("form_errors", res)
		self.assertEqual(res.get("search"), "doctor who")

		# Search term too short
		request = testing.DummyRequest(post={"search": "d"})
		request.session["auth.userid"] = "testuser1"
		ctl = SearchController(request)

		with self.assertRaises(ValidationFailure) as ctx:
			ctl.post(tvdb=tvdb_mock)

		request.exception = ctx.exception
		res = ctl.failure()

		self.assertIn("form_errors", res)
		errors = res.get("form_errors")
		self.assertEqual("Shorter than minimum length 2",
							errors.get("search"))
		self.assertEqual(res.get("search"), "d")

		# TVDB error
		request = testing.DummyRequest(post={
			"search": "something must be broken"
		})
		request.session["auth.userid"] = "testuser1"
		ctl = SearchController(request)

		request.exception = Exception()
		res = ctl.tvdb_failure()

		self.assertEqual(len(res.get("shows")), 0)
		self.assertNotIn("form_errors", res)
		self.assertEqual(res.get("search"), "something must be broken")

		msg = request.session.pop_flash("danger")
		self.assertEqual(1, len(msg))
		self.assertEqual("Failed to reach TheTVDB, search results will "
						"be incomplete.", msg[0])

	def testEpisodes(self):

		request = testing.DummyRequest()
		request.session['auth.userid'] = 'testuser1'
		ctl = EpisodesController(request)
		res = ctl.get()

		ep = res.get('episodes', [])
		self.assertEqual(2, len(ep))

		self.assertEqual('ep5', ep[0].title)
		self.assertEqual('ep2', ep[1].title)

		# 1 day back
		user = DBSession.query(User).get('testuser1')
		user.days_back = 1
		ctl = EpisodesController(request)
		res = ctl.get()

		ep = res.get('episodes', [])
		self.assertEqual(2, len(ep))

		# 2 days back
		user = DBSession.query(User).get('testuser1')
		user.days_back = 2
		ctl = EpisodesController(request)
		res = ctl.get()
		ep = res.get('episodes', [])
		self.assertEqual(3, len(ep))

		self.assertEqual('ep4', ep[0].title)
		self.assertEqual('ep5', ep[1].title)
		self.assertEqual('ep2', ep[2].title)

	def testFeed(self):

		request = testing.DummyRequest()
		request.session['auth.userid'] = 'testuser1'
		ctl = EpisodesController(request)
		res = ctl.feed()
		self.assertEqual(400, res.code)

		request = testing.DummyRequest()
		request.matchdict['user'] = 'testuser1'
		ctl = EpisodesController(request)
		res = ctl.feed()
		self.assertEqual(401, res.code)

		request = testing.DummyRequest()
		request.matchdict['user'] = 'testuser1'
		request.matchdict['token'] = 'wrong'
		ctl = EpisodesController(request)
		res = ctl.feed()
		self.assertEqual(401, res.code)

		request = testing.DummyRequest()
		request.matchdict['user'] = 'testuser1'
		request.matchdict['token'] = 'mytoken'
		ctl = EpisodesController(request)
		res = ctl.feed()

		ep = res.get('episodes', [])
		self.assertEqual(2, len(ep))

		self.assertEqual('ep5', ep[0].title)
		self.assertEqual('ep2', ep[1].title)

		# 1 day back
		user = DBSession.query(User).get('testuser1')
		user.days_back = 1
		ctl = EpisodesController(request)
		res = ctl.feed()

		ep = res.get('episodes', [])
		self.assertEqual(2, len(ep))

		# 2 days back
		user = DBSession.query(User).get('testuser1')
		user.days_back = 2
		ctl = EpisodesController(request)
		res = ctl.feed()
		ep = res.get('episodes', [])
		self.assertEqual(3, len(ep))

		self.assertEqual('ep4', ep[0].title)
		self.assertEqual('ep5', ep[1].title)
		self.assertEqual('ep2', ep[2].title)


class TestProfileView(WebisoderTest):

	def setUp(self):

		super(TestProfileView, self).setUp()
		MockUser.mockAuthentication()

		with transaction.manager:

			user = User(name="testuser11")
			user.password = "secret"
			DBSession.add(user)

			user = User(name="testuser12")
			user.password = "secret"
			user.mail = "init@set.up"
			user.link_format = "http://init.setup/"
			user.site_news = False
			user.days_back = 7
			user.date_offset = 1
			DBSession.add(user)

	def tearDown(self):

		with transaction.manager:

			user = DBSession.query(User).get("testuser11")
			DBSession.delete(user)

			user = DBSession.query(User).get("testuser12")
			DBSession.delete(user)

		MockUser.resetAuthentication()

		DBSession.remove()
		testing.tearDown()

	def testGetProfile(self):

		request = testing.DummyRequest()
		request.session["auth.userid"] = "testuser12"
		ctl = ProfileController(request)
		res = ctl.get()

		self.assertIn("user", res)
		user = res.get("user")
		self.assertEquals(user.name, "testuser12")

	def testUpdateEmailNoPassword(self):

		request = testing.DummyRequest({
			"email": "testuser@example.com",
		})
		request.session["auth.userid"] = "testuser12"
		ctl = ProfileController(request)

		with self.assertRaises(ValidationFailure) as ctx:
			ctl.post()

		request.exception = ctx.exception
		res = ctl.failure()

		self.assertIn("user", res)
		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual("Required", errors.get("password"))
		self.assertNotIn("email", errors)
		user = DBSession.query(User).get("testuser12")
		self.assertEqual(user.mail, "init@set.up")

	def testUpdateEmailWrongPassword(self):

		request = testing.DummyRequest({
			"email": "testuser@example.com",
			"password": "wrong"
		})
		request.session["auth.userid"] = "testuser12"
		ctl = ProfileController(request)

		with self.assertRaises(FormError) as ctx:
			ctl.post()

		request.exception = ctx.exception
		res = ctl.failure()

		self.assertIn("user", res)
		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual("Wrong password", errors.get("password"))
		self.assertNotIn("email", errors)
		user = DBSession.query(User).get("testuser12")
		self.assertEqual(user.mail, "init@set.up")

	def testUpdateEmailEmptyEmail(self):

		request = testing.DummyRequest({
			"email": "",
			"password": "secret"
		})
		request.session["auth.userid"] = "testuser12"
		ctl = ProfileController(request)

		with self.assertRaises(ValidationFailure) as ctx:
			ctl.post()

		request.exception = ctx.exception
		res = ctl.failure()

		self.assertIn("user", res)
		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual("Required", errors.get("email"))
		self.assertNotIn("password", errors)
		user = DBSession.query(User).get("testuser12")
		self.assertEqual(user.mail, "init@set.up")

	def testUpdateEmailInvalidAddress(self):

		request = testing.DummyRequest({
			"email": "notaproperaddress",
			"password": "secret"
		})
		request.session["auth.userid"] = "testuser12"
		ctl = ProfileController(request)

		with self.assertRaises(ValidationFailure) as ctx:
			ctl.post()

		request.exception = ctx.exception
		res = ctl.failure()

		self.assertIn("user", res)
		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual("Invalid email address", errors.get("email"))
		self.assertNotIn("password", errors)
		user = DBSession.query(User).get("testuser12")
		self.assertEqual(user.mail, "init@set.up")

	def testUpdateEmailEmptyRequest(self):

		request = testing.DummyRequest({})
		request.session['auth.userid'] = 'testuser12'
		ctl = ProfileController(request)

		with self.assertRaises(ValidationFailure) as ctx:
			ctl.post()

		request.exception = ctx.exception
		res = ctl.failure()

		self.assertIn("user", res)
		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual("Required", errors.get("email"))
		self.assertEqual("Required", errors.get("password"))
		user = DBSession.query(User).get("testuser12")
		self.assertEqual(user.mail, "init@set.up")

	def testUpdateEmail(self):

		request = testing.DummyRequest({
			"email": "testuser@example.com",
			"password": "secret"
		})
		request.session["auth.userid"] = "testuser12"
		ctl = ProfileController(request)
		res = ctl.post()
		user = DBSession.query(User).get("testuser12")
		self.assertEqual("testuser@example.com", user.mail)
		self.assertTrue(hasattr(res, "location"))
		self.assertTrue(res.location.endswith("__PROFILE__"))

	def testUpdateLinkFormatTooShort(self):

		request = testing.DummyRequest({
			"link_format": "asdfg",
			"days_back": "1",
			"date_offset": "0"
		})
		request.session["auth.userid"] = "testuser12"
		ctl = FeedSettingsController(request)

		with self.assertRaises(ValidationFailure) as ctx:
			ctl.post()

		request.exception = ctx.exception
		res = ctl.failure()

		self.assertIn("user", res)
		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual("Shorter than minimum length 6",
						errors.get("link_format"))
		self.assertNotIn("days_back", errors)
		self.assertNotIn("date_offset", errors)
		user = DBSession.query(User).get("testuser12")
		self.assertEqual("http://init.setup/", user.link_format)

	def testUpdateLinkFormatEmpty(self):

		request = testing.DummyRequest({
			"link_format": "",
			"days_back": "1",
			"date_offset": "0"
		})
		request.session["auth.userid"] = "testuser12"
		ctl = FeedSettingsController(request)

		with self.assertRaises(ValidationFailure) as ctx:
			ctl.post()

		request.exception = ctx.exception
		res = ctl.failure()

		self.assertIn("user", res)
		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual("Required", errors.get("link_format"))
		self.assertNotIn("days_back", errors)
		self.assertNotIn("date_offset", errors)
		user = DBSession.query(User).get("testuser12")
		self.assertEqual("http://init.setup/", user.link_format)

	def testUpdateLinkFormatMissing(self):

		request = testing.DummyRequest({
			"days_back": "1",
			"date_offset": "0"
		})
		request.session["auth.userid"] = "testuser12"
		ctl = FeedSettingsController(request)

		with self.assertRaises(ValidationFailure) as ctx:
			ctl.post()

		request.exception = ctx.exception
		res = ctl.failure()

		self.assertIn("user", res)
		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual("Required", errors.get("link_format"))
		self.assertNotIn("days_back", errors)
		self.assertNotIn("date_offset", errors)
		user = DBSession.query(User).get("testuser12")
		self.assertEqual("http://init.setup/", user.link_format)

	def testUpdateLinkFormat(self):

		request = testing.DummyRequest({
			"link_format": "http://www.example.com/",
			"days_back": "1",
			"date_offset": "0"
		})

		request.session["auth.userid"] = "testuser12"
		ctl = FeedSettingsController(request)
		res = ctl.post()

		user = DBSession.query(User).get("testuser12")
		self.assertNotIn("form_errors", res)
		self.assertEqual("http://www.example.com/", user.link_format)
		self.assertTrue(hasattr(res, "location"))
		self.assertTrue(res.location.endswith("__FEED__"))

	def testUpdateSiteNews(self):

		request = testing.DummyRequest({
			"email": "testuser@example.com",
			"site_news": "on",
			"password": "secret"
		})
		request.session["auth.userid"] = "testuser12"
		ctl = ProfileController(request)
		res = ctl.post()
		user = DBSession.query(User).get("testuser12")
		self.assertTrue(hasattr(res, "location"))
		self.assertTrue(res.location.endswith("__PROFILE__"))
		self.assertTrue(user.site_news)

	def testUpdateSiteNewsMissing(self):

		request = testing.DummyRequest({
			"email": "testuser@example.com",
			"password": "secret"
		})
		request.session["auth.userid"] = "testuser12"
		ctl = ProfileController(request)
		res = ctl.post()
		user = DBSession.query(User).get("testuser12")
		self.assertTrue(hasattr(res, "location"))
		self.assertTrue(res.location.endswith("__PROFILE__"))
		self.assertFalse(user.site_news)

	def testUpdateMaxAge(self):

		request = testing.DummyRequest({
			"days_back": "6",
			"link_format": "ignore",
			"date_offset": "0"
		})
		request.session["auth.userid"] = "testuser12"
		ctl = FeedSettingsController(request)
		res = ctl.post()
		user = DBSession.query(User).get("testuser12")
		self.assertEqual(6, user.days_back)
		self.assertTrue(hasattr(res, "location"))
		self.assertTrue(res.location.endswith("__FEED__"))

		request = testing.DummyRequest({
			"days_back": "7",
			"link_format": "ignore",
			"date_offset": "0"
		})
		request.session["auth.userid"] = "testuser12"
		ctl = FeedSettingsController(request)
		res = ctl.post()
		user = DBSession.query(User).get("testuser12")
		self.assertEqual(7, user.days_back)
		self.assertTrue(hasattr(res, "location"))
		self.assertTrue(res.location.endswith("__FEED__"))

	def testUpdateMaxAgeTooHigh(self):

		request = testing.DummyRequest({
			"days_back": "8",
			"link_format": "ignore",
			"date_offset": "0"
		})
		request.session["auth.userid"] = "testuser12"
		ctl = FeedSettingsController(request)

		with self.assertRaises(ValidationFailure) as ctx:
			ctl.post()

		request.exception = ctx.exception
		res = ctl.failure()

		self.assertIn("user", res)
		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual("8 is greater than maximum value 7",
							errors.get("days_back"))
		self.assertNotIn("link_format", errors)
		self.assertNotIn("date_offset", errors)
		user = DBSession.query(User).get("testuser12")
		self.assertEqual(7, user.days_back)

	def testUpdateMaxAgeTooLow(self):

		request = testing.DummyRequest({
			"days_back": "-1",
			"link_format": "ignore",
			"date_offset": "0"
		})
		request.session["auth.userid"] = "testuser12"
		ctl = FeedSettingsController(request)

		with self.assertRaises(ValidationFailure) as ctx:
			ctl.post()

		request.exception = ctx.exception
		res = ctl.failure()

		self.assertIn("user", res)
		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual("-1 is less than minimum value 1",
							errors.get("days_back"))
		self.assertNotIn("link_format", errors)
		self.assertNotIn("date_offset", errors)
		user = DBSession.query(User).get("testuser12")
		self.assertEqual(7, user.days_back)

	def testUpdateMaxAgeEmpty(self):

		request = testing.DummyRequest({
			"days_back": "",
			"link_format": "ignore",
			"date_offset": "0"
		})
		request.session["auth.userid"] = "testuser12"
		ctl = FeedSettingsController(request)

		with self.assertRaises(ValidationFailure) as ctx:
			ctl.post()

		request.exception = ctx.exception
		res = ctl.failure()

		self.assertIn("user", res)
		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual("Required", errors.get("days_back"))
		self.assertNotIn("link_format", errors)
		self.assertNotIn("date_offset", errors)
		user = DBSession.query(User).get("testuser12")
		self.assertEqual(7, user.days_back)

	def testUpdateMaxAgeNonInteger(self):

		request = testing.DummyRequest({
			"days_back": "nothing",
			"link_format": "ignore",
			"date_offset": "0"
		})
		request.session["auth.userid"] = "testuser12"
		ctl = FeedSettingsController(request)

		with self.assertRaises(ValidationFailure) as ctx:
			ctl.post()

		request.exception = ctx.exception
		res = ctl.failure()

		self.assertIn("user", res)
		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual('"nothing" is not a number',
							errors.get("days_back"))
		self.assertNotIn("link_format", errors)
		self.assertNotIn("date_offset", errors)
		user = DBSession.query(User).get("testuser12")
		self.assertEqual(7, user.days_back)

	def testupdateMaxAgeMissing(self):

		request = testing.DummyRequest({
			"link_format": "ignore",
			"date_offset": "0"
		})
		request.session["auth.userid"] = "testuser12"
		ctl = FeedSettingsController(request)

		with self.assertRaises(ValidationFailure) as ctx:
			ctl.post()

		request.exception = ctx.exception
		res = ctl.failure()

		self.assertIn("user", res)
		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual("Required", errors.get("days_back"))
		self.assertNotIn("link_format", errors)
		self.assertNotIn("date_offset", errors)
		user = DBSession.query(User).get("testuser12")
		self.assertEqual(7, user.days_back)

	def testUpdateOffset(self):

		request = testing.DummyRequest({
			"email": "testuser@example.com",
			"link_format": "ignore",
			"days_back": "1",
			"date_offset": "0"
		})
		request.session["auth.userid"] = "testuser12"
		ctl = FeedSettingsController(request)
		res = ctl.post()
		user = DBSession.query(User).get("testuser12")
		self.assertEqual(0, user.date_offset)
		self.assertTrue(hasattr(res, "location"))
		self.assertTrue(res.location.endswith("__FEED__"))

		request = testing.DummyRequest({
			"email": "testuser@example.com",
			"link_format": "ignore",
			"days_back": "1",
			"date_offset": "2"
		})
		request.session["auth.userid"] = "testuser12"
		ctl = FeedSettingsController(request)
		res = ctl.post()
		user = DBSession.query(User).get("testuser12")
		self.assertEqual(2, user.date_offset)
		self.assertTrue(hasattr(res, "location"))
		self.assertTrue(res.location.endswith("__FEED__"))

	def testUpdateOffsetTooSmall(self):

		request = testing.DummyRequest({
			"email": "testuser@example.com",
			"link_format": "ignore",
			"days_back": "1",
			"date_offset": "-1"
		})
		request.session["auth.userid"] = "testuser12"
		ctl = FeedSettingsController(request)

		with self.assertRaises(ValidationFailure) as ctx:
			ctl.post()

		request.exception = ctx.exception
		res = ctl.failure()

		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual("-1 is less than minimum value 0",
						errors.get("date_offset"))
		user = DBSession.query(User).get("testuser12")
		self.assertEqual(1, user.date_offset)

	def testUpdateOffsetTooLarge(self):

		request = testing.DummyRequest({
			"email": "testuser@example.com",
			"link_format": "ignore",
			"days_back": "1",
			"date_offset": "3"
		})
		request.session["auth.userid"] = "testuser12"
		ctl = FeedSettingsController(request)

		with self.assertRaises(ValidationFailure) as ctx:
			ctl.post()

		request.exception = ctx.exception
		res = ctl.failure()

		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual("3 is greater than maximum value 2",
						errors.get("date_offset"))
		user = DBSession.query(User).get("testuser12")
		self.assertEqual(1, user.date_offset)

	def testUpdateOffsetNotAnInteger(self):

		request = testing.DummyRequest({
			"email": "testuser@example.com",
			"link_format": "ignore",
			"days_back": "1",
			"date_offset": "A"
		})
		request.session["auth.userid"] = "testuser12"
		ctl = FeedSettingsController(request)

		with self.assertRaises(ValidationFailure) as ctx:
			ctl.post()

		request.exception = ctx.exception
		res = ctl.failure()

		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual('"A" is not a number',
						errors.get("date_offset"))
		user = DBSession.query(User).get("testuser12")
		self.assertEqual(1, user.date_offset)

	def testUpdateOffsetMissing(self):

		request = testing.DummyRequest({
			"email": "testuser@example.com",
			"link_format": "ignore",
			"days_back": "1"
		})
		request.session["auth.userid"] = "testuser12"
		ctl = FeedSettingsController(request)

		with self.assertRaises(ValidationFailure) as ctx:
			ctl.post()

		request.exception = ctx.exception
		res = ctl.failure()

		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual("Required", errors.get("date_offset"))
		user = DBSession.query(User).get("testuser12")
		self.assertEqual(1, user.date_offset)

	def testUpdatePasswordMissingOld(self):

		request = testing.DummyRequest({
			"new": "asdf",
			"verify": "asdf"
		})
		request.session["auth.userid"] = "testuser12"
		ctl = PasswordChangeController(request)

		with self.assertRaises(ValidationFailure) as ctx:
			res = ctl.post()

		request.exception = ctx.exception
		res = ctl.failure()

		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual("Shorter than minimum length 6",
							errors.get("new"))
		self.assertEqual("Required", errors.get("current"))
		user = DBSession.query(User).get("testuser12")
		self.assertTrue(user.authenticate("secret"))

	def testUpdatePasswordMissingNew(self):

		request = testing.DummyRequest({
			'current': 'asdf',
			'verify': 'asdf'
		})
		request.session['auth.userid'] = 'testuser12'
		ctl = PasswordChangeController(request)

		with self.assertRaises(ValidationFailure) as ctx:
			res = ctl.post()

		request.exception = ctx.exception
		res = ctl.failure()

		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual("Required", errors.get("new"))
		user = DBSession.query(User).get("testuser12")
		self.assertTrue(user.authenticate("secret"))
		self.assertIn("user", res)

	def testUpdatePasswordMissingVerify(self):

		request = testing.DummyRequest({
			'current': 'asdf',
			'new': 'asdf'
		})
		request.session['auth.userid'] = 'testuser12'
		ctl = PasswordChangeController(request)

		with self.assertRaises(ValidationFailure) as ctx:
			res = ctl.post()

		request.exception = ctx.exception
		res = ctl.failure()

		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual("Shorter than minimum length 6",
							errors.get("new"))
		self.assertEqual("Required", errors.get("verify"))
		user = DBSession.query(User).get("testuser12")
		self.assertTrue(user.authenticate("secret"))
		self.assertIn("user", res)

	def testUpdatePasswordWrongOld(self):

		request = testing.DummyRequest({
			'current': 'asdf',
			'new': 'asdfgh',
			'verify': 'asdfgh'
		})
		request.session['auth.userid'] = 'testuser12'
		ctl = PasswordChangeController(request)

		with self.assertRaises(FormError) as ctx:
			res = ctl.post()

		request.exception = ctx.exception
		res = ctl.failure()

		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual("Wrong password", errors.get("current"))
		user = DBSession.query(User).get("testuser12")
		self.assertTrue(user.authenticate("secret"))
		self.assertIn("user", res)

	def testUpdatePasswordTooShort(self):

		request = testing.DummyRequest({
			'current': 'secret',
			'new': 'asdfg',
			'verify': 'asdfg'
		})
		request.session['auth.userid'] = 'testuser12'
		ctl = PasswordChangeController(request)

		with self.assertRaises(ValidationFailure) as ctx:
			res = ctl.post()

		request.exception = ctx.exception
		res = ctl.failure()

		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual("Shorter than minimum length 6",
							errors.get("new"))
		user = DBSession.query(User).get("testuser12")
		self.assertTrue(user.authenticate("secret"))
		self.assertIn("user", res)

	def testUpdatePasswordWrongVerify(self):

		request = testing.DummyRequest({
			'current': 'secret',
			'new': 'asdfgh',
			'verify': 'asdfghi'
		})
		request.session['auth.userid'] = 'testuser12'
		ctl = PasswordChangeController(request)

		with self.assertRaises(FormError) as ctx:
			res = ctl.post()

		request.exception = ctx.exception
		res = ctl.failure()

		errors = res.get("form_errors")
		self.assertIsNotNone(errors)
		self.assertEqual("Passwords do not match", errors.get("verify"))
		user = DBSession.query(User).get("testuser12")
		self.assertTrue(user.authenticate("secret"))
		self.assertIn("user", res)

	def testUpdatePassword(self):

		request = testing.DummyRequest({
			'current': 'secret',
			'new': 'asdfgh',
			'verify': 'asdfgh'
		})

		request.session['auth.userid'] = 'testuser12'
		ctl = PasswordChangeController(request)
		res = ctl.post()
		user = DBSession.query(User).get('testuser12')
		self.assertTrue(hasattr(res, 'location'))
		self.assertTrue(res.location.endswith('__PW__'))
		self.assertTrue(user.authenticate("asdfgh"))

	def testResetToken(self):

		request = testing.DummyRequest()
		request.session['auth.userid'] = 'testuser12'

		user = DBSession.query(User).get('testuser12')
		token = user.token

		ctl = TokenResetController(request)
		res = ctl.post()
		self.assertTrue(hasattr(res, 'location'))
		self.assertTrue(res.location.endswith('__TOKEN__'))
		user = DBSession.query(User).get('testuser12')
		self.assertNotEqual(token, user.token)
		token = user.token

		ctl = TokenResetController(request)
		res = ctl.post()
		self.assertTrue(hasattr(res, 'location'))
		self.assertTrue(res.location.endswith('__TOKEN__'))
		user = DBSession.query(User).get('testuser12')
		self.assertNotEqual(token, user.token)


class TestIndexPage(WebisoderTest):

	def setUp(self):

		super(TestIndexPage, self).setUp()

	def tearDown(self):

		testing.tearDown()

	def testNoUser(self):

		request = testing.DummyRequest()

		ctl = IndexController(request)
		res = ctl.get()
		self.assertFalse(hasattr(res, "location"))

	def testUser(self):

		request = testing.DummyRequest()
		request.session["auth.userid"] = "testuser1"

		ctl = IndexController(request)
		res = ctl.get()
		self.assertTrue(hasattr(res, "location"))
		self.assertTrue(res.location.endswith("__SHOWS__"))


class TestMailClasses(WebisoderTest):

	def setUp(self):

		super(TestMailClasses, self).setUp()
		self.config.include("pyramid_chameleon")
		self.config.include('pyramid_mailer.testing')

	def tearDown(self):

		testing.tearDown()

	def testWelcomeMessage(self):

		request = testing.DummyRequest()

		msg = WelcomeMessage()
		user = User()
		user.mail = "2008@example.org"
		user.name = "User 2008"

		mailer = get_mailer(request)
		self.assertEqual(len(mailer.outbox), 0)

		msg.send(request, user, "s3kr1t")
		self.assertEqual(len(mailer.outbox), 1)

		message = mailer.outbox[0]
		self.assertEqual(message.subject, "New user registration")
		self.assertEqual(message.sender, "noreply@webisoder.net")
		self.assertEqual(len(message.recipients), 1)
		self.assertIn("2008@example.org", message.recipients)
		self.assertIn("User 2008", message.body)
		self.assertIn("your initial password is", message.body)
		self.assertIn("s3kr1t", message.body)

	def testWelcomeMessageFailure(self):

		def fail_mail(self, msg, fail_silently=False):

			raise Exception()

		request = testing.DummyRequest()
		mailer = get_mailer(request)
		mailer.send_immediately = fail_mail

		msg = WelcomeMessage()
		request = testing.DummyRequest()
		user = User()
		user.mail = "2008@example.org"
		user.name = "User 2008"

		mailer = get_mailer(request)
		self.assertEqual(len(mailer.outbox), 0)

		with self.assertRaises(MailError):
			msg.send(request, user, "s3kr1t")

		self.assertEqual(len(mailer.outbox), 0)

	def testPasswordRecoveryMessage(self):

		request = testing.DummyRequest()

		msg = PasswordRecoveryMessage()
		user = User()
		user.mail = "2102@example.org"
		user.name = "User 2102"

		mailer = get_mailer(request)
		self.assertEqual(len(mailer.outbox), 0)

		msg.send(request, user)
		self.assertEqual(len(mailer.outbox), 1)

		message = mailer.outbox[0]
		self.assertEqual(message.subject, "Webisoder password recovery")
		self.assertEqual(message.sender, "noreply@webisoder.net")
		self.assertEqual(len(message.recipients), 1)
		self.assertIn("2102@example.org", message.recipients)
		self.assertIn("User 2102", message.body)
		self.assertIn("To reset your password", message.body)
		self.assertNotIn("__RECOVER__", message.body)
		self.assertIn("__REC__", message.body)
		self.assertIn("__LOGIN__", message.body)

	def testPasswordRecoveryMessageFailure(self):

		def fail_mail(self, msg, fail_silently=False):

			raise Exception()

		request = testing.DummyRequest()
		mailer = get_mailer(request)
		mailer.send_immediately = fail_mail

		msg = PasswordRecoveryMessage()
		user = User()
		user.mail = "2102@example.org"
		user.name = "User 2102"

		mailer = get_mailer(request)
		self.assertEqual(len(mailer.outbox), 0)

		with self.assertRaises(MailError):
			msg.send(request, user)

		self.assertEqual(len(mailer.outbox), 0)
