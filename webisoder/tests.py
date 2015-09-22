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

import unittest
import transaction

from datetime import date, timedelta
from pyramid import testing
from pyramid.exceptions import BadCSRFToken
from sqlalchemy import create_engine

from .models import DBSession
from .models import Base, Show, Episode, User

from .views import login, logout, shows, subscribe, unsubscribe, search_post
from .views import index, episodes, profile_get, profile_post, password_post
from .views import settings_token_post, settings_feed_post

class WebisoderModelTests(unittest.TestCase):

	def setUp(self):

		super(WebisoderModelTests, self).setUp()
		self.config = testing.setUp()
		engine = create_engine('sqlite://')
		DBSession.configure(bind=engine)
		Base.metadata.create_all(engine)

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

		DBSession.remove()
		testing.tearDown()

	def test_user_token(self):

		user1 = DBSession.query(User).get('user1')
		user1.token = 'token'

		user1.reset_token()
		token = user1.token
		self.assertNotEqual(token, 'token')
		self.assertEqual(12, len(token))

		user1.reset_token()
		self.assertNotEqual(token, user1.token)
		self.assertEqual(12, len(token))

	def test_show_episode_relation(self):

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

	def test_subscriptions(self):

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

	def test_user_episodes(self):

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

	def test_authentication(self):

		user = DBSession.query(User).get('user1')
		user.salt = ''
		user.password = 'letmein'

		self.assertTrue(user.authenticate('letmein'))
		self.assertNotEqual('', user.salt)

	def test_upgrade_password(self):

		user = DBSession.query(User).get('user1')
		user.passwd = '0d107d09f5bbe40cade3de5c71e9e9b7'
		user.salt = ''

		self.assertEqual('0d107d09f5bbe40cade3de5c71e9e9b7', user.passwd)
		self.assertEqual('', user.salt)

		self.assertTrue(user.authenticate('letmein'))
		self.assertNotEqual('', user.salt)
		self.assertNotEqual('0d107d09f5bbe40cade3de5c71e9e9b7', user.passwd)

		self.assertTrue(user.authenticate('letmein'))

	def test_render_episode(self):

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

	def test_next_episode(self):

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

class TestAuthenticationAndAuthorization(unittest.TestCase):

	def setUp(self):

		super(TestAuthenticationAndAuthorization, self).setUp()
		self.config = testing.setUp()
		self.config.add_route('shows', '__SHOWS__')
		self.config.add_route('home', '__HOME__')

		engine = create_engine('sqlite://')
		DBSession.configure(bind=engine)
		Base.metadata.create_all(engine)

		with transaction.manager:

			user = User(name='testuser100')
			user.password = 'secret'
			DBSession.add(user)

	def tearDown(self):

		user = DBSession.query(User).get('testuser100')
		DBSession.delete(user)

		DBSession.remove()
		testing.tearDown()

	def testInvalidCSRFToken(self):

		request = testing.DummyRequest(post={
			'user': 'testuser2',
			'password': 'secret'
		})

		with self.assertRaises(BadCSRFToken):
			res = login(request)

	def testInvalidUserName(self):

		request = testing.DummyRequest(post={
			'user': 'testuser2',
			'password': 'secret'
		})
		request.params['csrf_token'] = request.session.get_csrf_token()

		res = login(request)
		self.assertNotIn('user', request.session)
		self.assertFalse(hasattr(res, 'location'))

		msg = request.session.pop_flash('warning')
		self.assertEqual(1, len(msg))
		self.assertEqual('Login failed', msg[0])

	def testEmptyUserName(self):

		request = testing.DummyRequest(post={
			'user': '',
			'password': 'wrong'
		})
		request.params['csrf_token'] = request.session.get_csrf_token()

		res = login(request)
		self.assertNotIn('user', request.session)
		self.assertFalse(hasattr(res, 'location'))

		msg = request.session.pop_flash('warning')
		self.assertEqual(1, len(msg))
		self.assertEqual('Login failed', msg[0])

	def testMissingUserName(self):

		request = testing.DummyRequest(post={
			'password': 'wrong'
		})
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = login(request)
		self.assertNotIn('user', request.session)
		self.assertFalse(hasattr(res, 'location'))

		msg = request.session.pop_flash('warning')
		self.assertEqual(1, len(msg))
		self.assertEqual('Login failed', msg[0])

	def testInvalidPassword(self):

		request = testing.DummyRequest(post={
			'user': 'testuser100',
			'password': 'wrong'
		})
		request.params['csrf_token'] = request.session.get_csrf_token()

		res = login(request)
		self.assertNotIn('user', request.session)
		self.assertFalse(hasattr(res, 'location'))

		msg = request.session.pop_flash('warning')
		self.assertEqual(1, len(msg))
		self.assertEqual('Login failed', msg[0])

	def testEmptyPassword(self):

		request = testing.DummyRequest(post={
			'user': 'testuser100',
			'password': ''
		})
		request.params['csrf_token'] = request.session.get_csrf_token()

		res = login(request)
		self.assertNotIn('user', request.session)
		self.assertFalse(hasattr(res, 'location'))

		msg = request.session.pop_flash('warning')
		self.assertEqual(1, len(msg))
		self.assertEqual('Login failed', msg[0])

	def testMissingPassword(self):

		request = testing.DummyRequest(post={
			'user': 'testuser100'
		})
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = login(request)
		self.assertNotIn('user', request.session)
		self.assertFalse(hasattr(res, 'location'))

		msg = request.session.pop_flash('warning')
		self.assertEqual(1, len(msg))
		self.assertEqual('Login failed', msg[0])

	def testLoginLogout(self):

		request = testing.DummyRequest(post={
			'user': 'testuser100',
			'password': 'secret'
		})
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = login(request)

		self.assertTrue(hasattr(res, 'location'))
		self.assertTrue(res.location.endswith('__SHOWS__'))

		self.assertIn('user', request.session)
		self.assertEqual('testuser100', request.session['user'])

		msg = request.session.pop_flash('warning')
		self.assertEqual(0, len(msg))

		msg = request.session.pop_flash('info')
		self.assertEqual(0, len(msg))

		res = logout(request)
		self.assertTrue(hasattr(res, 'location'))
		self.assertTrue(res.location.endswith('__HOME__'))
		self.assertNotIn('user', request.session)

		msg = request.session.pop_flash('info')
		self.assertEqual(1, len(msg))
		self.assertEqual('Successfully signed out. Goodbye.', msg[0])

class TestShowsView(unittest.TestCase):

	def setUp(self):

		super(TestShowsView, self).setUp()
		self.config = testing.setUp()
		self.config.add_route('shows', '__SHOWS__')

		engine = create_engine('sqlite://')
		DBSession.configure(bind=engine)
		Base.metadata.create_all(engine)

		with transaction.manager:

			user = User(name='testuser1')
			user.password = 'secret'
			user.days_back = 0
			DBSession.add(user)

			self.show1 = Show(id=1, name='show1', url='http://1')
			self.show2 = Show(id=2, name='show2', url='http://2')
			self.show3 = Show(id=3, name='show3', url='http://3')
			self.show4 = Show(id=4, name='show4', url='http://4')

			user.shows.append(self.show1)
			user.shows.append(self.show2)
			user.shows.append(self.show3)

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

		DBSession.remove()
		testing.tearDown()

	def testShowList(self):

		request = testing.DummyRequest()
		request.session['user'] = 'testuser1'
		res = shows(request)

		result_shows = [x.id for x in res['subscribed']]
		self.assertIn(1, result_shows)
		self.assertIn(2, result_shows)
		self.assertIn(3, result_shows)
		self.assertNotIn(4, result_shows)

	def testSubscribeShow(self):

		request = testing.DummyRequest()
		request.session['user'] = 'testuser1'

		with self.assertRaises(BadCSRFToken):
			res = subscribe(request)

		request = testing.DummyRequest()
		request.session['user'] = 'testuser1'
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = subscribe(request)
		self.assertEqual(res.get('error'), 'no show specified')

		request = testing.DummyRequest(post={'show': 'a'})
		request.session['user'] = 'testuser1'
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = subscribe(request)
		self.assertEqual(res.get('error'), 'illegal show id')

		request = testing.DummyRequest(post={'show': '5'})
		request.session['user'] = 'testuser1'
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = subscribe(request)
		self.assertEqual(res.get('error'), 'no such show')

		request = testing.DummyRequest(post={'show': '4'})
		request.session['user'] = 'testuser1'
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = subscribe(request)
		self.assertTrue(hasattr(res, 'location'))
		self.assertTrue(res.location.endswith('__SHOWS__'))

		msg = request.session.pop_flash('info')
		self.assertEqual(1, len(msg))
		self.assertEqual('Successfully subscribed to "show4"', msg[0])

		res = shows(request)

		result_shows = [x.id for x in res['subscribed']]
		self.assertIn(1, result_shows)
		self.assertIn(2, result_shows)
		self.assertIn(3, result_shows)
		self.assertIn(4, result_shows)

	def testUnsubscribeShow(self):

		request = testing.DummyRequest()
		request.session['user'] = 'testuser1'
		with self.assertRaises(BadCSRFToken):
			res = unsubscribe(request)

		request = testing.DummyRequest()
		request.session['user'] = 'testuser1'
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = unsubscribe(request)
		self.assertTrue(hasattr(res, 'location'))
		self.assertTrue(res.location.endswith('__SHOWS__'))

		request = testing.DummyRequest(post={'show': 'a'})
		request.session['user'] = 'testuser1'
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = unsubscribe(request)
		self.assertTrue(hasattr(res, 'location'))
		self.assertTrue(res.location.endswith('__SHOWS__'))

		request = testing.DummyRequest(post={'show': '5'})
		request.session['user'] = 'testuser1'
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = unsubscribe(request)
		self.assertTrue(hasattr(res, 'code'))
		self.assertEqual(res.code, 404)

		request = testing.DummyRequest(post={'show': '3'})
		request.session['user'] = 'testuser1'
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = unsubscribe(request)
		self.assertTrue(hasattr(res, 'location'))
		self.assertTrue(res.location.endswith('__SHOWS__'))

		msg = request.session.pop_flash('info')
		self.assertEqual(1, len(msg))
		self.assertEqual('Successfully unsubscribed from "show3"', msg[0])

		res = shows(request)

		result_shows = [x.id for x in res['subscribed']]
		self.assertIn(1, result_shows)
		self.assertIn(2, result_shows)
		self.assertNotIn(3, result_shows)
		self.assertNotIn(4, result_shows)

	def test_search(self):

		class mock_show(object):

			def __init__(self, id):
				self.attr = {}
				self.attr['id'] = id

			def get(self, attr):
				return self.attr.get(attr)

		class tvdb_mock():

			def __init__(self, custom_ui=None):
				self.items = {
					'big bang theory': [ mock_show(80379) ],
					'doctor who': [
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

		request = testing.DummyRequest(post={'bla': 'big bang'})
		request.session['user'] = 'testuser1'
		res = search_post(request, tvdb=tvdb_mock)
		self.assertIn('form_errors', res)
		errors = res.get('form_errors')
		self.assertIn('search', errors)
		error = errors.get('search')
		self.assertEqual(error, 'Required')
		self.assertIn('search', res)
		search = res.get('search')
		self.assertEqual(search, '')

		request = testing.DummyRequest(post={'search': 'big bang theory'})
		request.session['user'] = 'testuser1'
		res = search_post(request, tvdb=tvdb_mock)
		self.assertEqual(len(res.get('shows')), 1)
		self.assertEqual(res.get('search'), 'big bang theory')
		show = res.get('shows')[0]
		self.assertEqual(show.get('id'), 80379)
		self.assertIn('form_errors', res)
		self.assertIn('search', res)
		search = res.get('search')
		self.assertEqual(search, 'big bang theory')

		request = testing.DummyRequest(post={'search': 'this does not exist'})
		request.session['user'] = 'testuser1'
		res = search_post(request, tvdb=tvdb_mock)
		self.assertEqual(len(res.get('shows')), 0)
		self.assertIn('form_errors', res)
		self.assertIn('search', res)
		search = res.get('search')
		self.assertEqual(search, 'this does not exist')

		request = testing.DummyRequest(post={'search': 'doctor who'})
		request.session['user'] = 'testuser1'
		res = search_post(request, tvdb=tvdb_mock)
		self.assertTrue(len(res.get('shows')) > 5)
		self.assertIn('form_errors', res)
		self.assertIn('search', res)
		search = res.get('search')
		self.assertEqual(search, 'doctor who')

		request = testing.DummyRequest(post={'search': 'do'})
		request.session['user'] = 'testuser1'
		res = search_post(request, tvdb=tvdb_mock)
		self.assertIn('form_errors', res)
		self.assertIn('search', res)
		search = res.get('search')
		self.assertEqual(search, 'do')

	def test_episodes(self):

		request = testing.DummyRequest()
		request.session['user'] = 'testuser1'
		res = episodes(request)

		ep = res.get('episodes', [])
		self.assertEqual(2, len(ep))

		self.assertEqual('ep5', ep[0].title)
		self.assertEqual('ep2', ep[1].title)

		# 1 day back
		user = DBSession.query(User).get('testuser1')
		user.days_back = 1
		res = episodes(request)

		ep = res.get('episodes', [])
		self.assertEqual(2, len(ep))

		# 2 days back
		user = DBSession.query(User).get('testuser1')
		user.days_back = 2
		res = episodes(request)
		ep = res.get('episodes', [])
		self.assertEqual(3, len(ep))

		self.assertEqual('ep4', ep[0].title)
		self.assertEqual('ep5', ep[1].title)
		self.assertEqual('ep2', ep[2].title)

class TestProfileView(unittest.TestCase):

	def setUp(self):

		super(TestProfileView, self).setUp()
		self.config = testing.setUp()
		self.config.add_route('profile', '__PROFILE__')
		self.config.add_route('settings_token', '__TOKEN__')
		self.config.add_route('settings_pw', '__PW__')
		self.config.add_route('settings_feed', '__FEED__')

		with transaction.manager:

			user = User(name='testuser11')
			user.password = 'secret'
			DBSession.add(user)

			user = User(name='testuser12')
			user.password = 'secret'
			DBSession.add(user)

	def tearDown(self):

		with transaction.manager:

			user = DBSession.query(User).get('testuser11')
			DBSession.delete(user)

			user = DBSession.query(User).get('testuser12')
			DBSession.delete(user)

		DBSession.remove()
		testing.tearDown()

	def testGetProfile(self):

		request = testing.DummyRequest()
		request.session['user'] = 'testuser12'
		res = profile_get(request)

		self.assertIn('user', res)
		user = res.get('user')
		self.assertEquals(user.name, 'testuser12')

	def testUpdateEmail(self):

		request = testing.DummyRequest({
			'email': 'testuser@example.com',
		})
		request.session['user'] = 'testuser12'
		with self.assertRaises(BadCSRFToken):
			res = profile_post(request)

		request = testing.DummyRequest({
			'email': 'testuser@example.com',
		})
		request.session['user'] = 'testuser12'
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = profile_post(request)
		user = user = DBSession.query(User).get('testuser12')
		self.assertEqual('testuser@example.com', user.mail)
		self.assertTrue(hasattr(res, 'location'))
		self.assertTrue(res.location.endswith('__PROFILE__'))

		request = testing.DummyRequest({
			'email': '',
		})
		request.session['user'] = 'testuser12'
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = profile_post(request)
		user = user = DBSession.query(User).get('testuser12')
		self.assertEqual('testuser@example.com', user.mail)
		self.assertIn('form_errors', res)
		self.assertIn('email', res.get('form_errors', {}))

		request = testing.DummyRequest({
			'email': 'notaproperaddress',
		})
		request.session['user'] = 'testuser12'
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = profile_post(request)
		user = user = DBSession.query(User).get('testuser12')
		self.assertEqual('testuser@example.com', user.mail)
		self.assertIn('form_errors', res)
		self.assertIn('email', res.get('form_errors', {}))

		request = testing.DummyRequest({})
		request.session['user'] = 'testuser12'
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = profile_post(request)
		user = user = DBSession.query(User).get('testuser12')
		self.assertEqual('testuser@example.com', user.mail)
		self.assertIn('form_errors', res)
		self.assertIn('email', res.get('form_errors', {}))

	def testUpdateLinkFormat(self):

		request = testing.DummyRequest({
			'link_format': 'http://www.example.com/',
			'days_back': '1',
			'date_offset': '0'
		})
		request.session['user'] = 'testuser12'
		with self.assertRaises(BadCSRFToken):
			res = settings_feed_post(request)

		request = testing.DummyRequest({
			'link_format': 'http://www.example.com/',
			'days_back': '1',
			'date_offset': '0'
		})
		request.session['user'] = 'testuser12'
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = settings_feed_post(request)
		user = user = DBSession.query(User).get('testuser12')
		self.assertEqual('http://www.example.com/', user.link_format)
		self.assertTrue(hasattr(res, 'location'))
		self.assertTrue(res.location.endswith('__FEED__'))

		request = testing.DummyRequest({
			'link_format': 'asdfg',
			'days_back': '1',
			'date_offset': '0'
		})
		request.session['user'] = 'testuser12'
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = settings_feed_post(request)
		user = user = DBSession.query(User).get('testuser12')
		self.assertEqual('http://www.example.com/', user.link_format)
		self.assertIn('form_errors', res)
		self.assertIn('link_format', res.get('form_errors', {}))

		request = testing.DummyRequest({
			'link_format': '',
			'days_back': '1',
			'date_offset': '0'
		})
		request.session['user'] = 'testuser12'
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = settings_feed_post(request)
		user = user = DBSession.query(User).get('testuser12')
		self.assertEqual('http://www.example.com/', user.link_format)
		self.assertIn('form_errors', res)
		self.assertIn('link_format', res.get('form_errors', {}))

		request = testing.DummyRequest({
			'days_back': '1',
			'date_offset': '0'
		})
		request.session['user'] = 'testuser12'
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = settings_feed_post(request)
		user = user = DBSession.query(User).get('testuser12')
		self.assertEqual('http://www.example.com/', user.link_format)
		self.assertIn('form_errors', res)
		self.assertIn('link_format', res.get('form_errors', {}))

		request = testing.DummyRequest({
			'link_format': 'https://www.example.com/',
			'days_back': '1',
			'date_offset': '0'
		})
		request.session['user'] = 'testuser12'
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = settings_feed_post(request)
		user = user = DBSession.query(User).get('testuser12')
		self.assertEqual('https://www.example.com/', user.link_format)
		self.assertTrue(hasattr(res, 'location'))
		self.assertTrue(res.location.endswith('__FEED__'))

	def testUpdateSiteNews(self):

		request = testing.DummyRequest({
			'email': 'testuser@example.com',
			'site_news': 'on',
		})
		request.session['user'] = 'testuser12'
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = profile_post(request)
		user = user = DBSession.query(User).get('testuser12')
		self.assertTrue(hasattr(res, 'location'))
		self.assertTrue(res.location.endswith('__PROFILE__'))
		self.assertTrue(user.site_news)

		request = testing.DummyRequest({
			'email': 'testuser@example.com',
		})
		request.session['user'] = 'testuser12'
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = profile_post(request)
		user = user = DBSession.query(User).get('testuser12')
		self.assertTrue(hasattr(res, 'location'))
		self.assertTrue(res.location.endswith('__PROFILE__'))
		self.assertFalse(user.site_news)

		request = testing.DummyRequest({
			'email': 'testuser@example.com',
			'site_news': 'on',
		})
		request.session['user'] = 'testuser12'
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = profile_post(request)
		user = user = DBSession.query(User).get('testuser12')
		self.assertTrue(hasattr(res, 'location'))
		self.assertTrue(res.location.endswith('__PROFILE__'))
		self.assertTrue(user.site_news)

	def testUpdateMaxAge(self):

		request = testing.DummyRequest({
			'days_back': '6',
			'link_format': 'ignore',
			'date_offset': '0'
		})
		request.session['user'] = 'testuser12'
		request.params['csrf_token'] = request.session.get_csrf_token()
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = settings_feed_post(request)
		user = DBSession.query(User).get('testuser12')
		self.assertEqual(6, user.days_back)
		self.assertTrue(hasattr(res, 'location'))
		self.assertTrue(res.location.endswith('__FEED__'))

		request = testing.DummyRequest({
			'days_back': '7',
			'link_format': 'ignore',
			'date_offset': '0'
		})
		request.session['user'] = 'testuser12'
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = settings_feed_post(request)
		user = DBSession.query(User).get('testuser12')
		self.assertEqual(7, user.days_back)
		self.assertTrue(hasattr(res, 'location'))
		self.assertTrue(res.location.endswith('__FEED__'))

		request = testing.DummyRequest({
			'days_back': '8',
			'link_format': 'ignore',
			'date_offset': '0'
		})
		request.session['user'] = 'testuser12'
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = settings_feed_post(request)
		user = DBSession.query(User).get('testuser12')
		self.assertEqual(7, user.days_back)
		self.assertIn('form_errors', res)
		self.assertIn('days_back', res.get('form_errors', {}))

		request = testing.DummyRequest({
			'days_back': '-1',
			'link_format': 'ignore',
			'date_offset': '0'
		})
		request.session['user'] = 'testuser12'
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = settings_feed_post(request)
		user = DBSession.query(User).get('testuser12')
		self.assertEqual(7, user.days_back)
		self.assertIn('form_errors', res)
		self.assertIn('days_back', res.get('form_errors', {}))

		request = testing.DummyRequest({
			'days_back': '',
			'link_format': 'ignore',
			'date_offset': '0'
		})
		request.session['user'] = 'testuser12'
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = settings_feed_post(request)
		user = DBSession.query(User).get('testuser12')
		self.assertEqual(7, user.days_back)
		self.assertIn('form_errors', res)
		self.assertIn('days_back', res.get('form_errors', {}))

		request = testing.DummyRequest({
			'days_back': 'nothing',
			'link_format': 'ignore',
			'date_offset': '0'
		})
		request.session['user'] = 'testuser12'
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = settings_feed_post(request)
		user = DBSession.query(User).get('testuser12')
		self.assertEqual(7, user.days_back)
		self.assertIn('form_errors', res)
		self.assertIn('days_back', res.get('form_errors', {}))

		request = testing.DummyRequest({
			'link_format': 'ignore',
			'date_offset': '0'
		})
		request.session['user'] = 'testuser12'
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = settings_feed_post(request)
		user = DBSession.query(User).get('testuser12')
		self.assertEqual(7, user.days_back)
		self.assertIn('form_errors', res)
		self.assertIn('days_back', res.get('form_errors', {}))

	def testUpdateOffset(self):

		request = testing.DummyRequest({
			'email': 'testuser@example.com',
			'link_format': 'ignore',
			'days_back': '1',
			'date_offset': '0'
		})
		request.session['user'] = 'testuser12'
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = settings_feed_post(request)
		user = DBSession.query(User).get('testuser12')
		self.assertEqual(0, user.date_offset)
		self.assertTrue(hasattr(res, 'location'))
		self.assertTrue(res.location.endswith('__FEED__'))

		request = testing.DummyRequest({
			'email': 'testuser@example.com',
			'link_format': 'ignore',
			'days_back': '1',
			'date_offset': '-1'
		})
		request = testing.DummyRequest({'date_offset': '0'})
		request.session['user'] = 'testuser12'
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = settings_feed_post(request)
		user = DBSession.query(User).get('testuser12')
		self.assertEqual(0, user.date_offset)
		self.assertIn('form_errors', res)
		self.assertNotIn('date_offset', res.get('form_errors', {}))

		request = testing.DummyRequest({
			'email': 'testuser@example.com',
			'link_format': 'ignore',
			'days_back': '1',
			'date_offset': '1'
		})
		request.session['user'] = 'testuser12'
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = settings_feed_post(request)
		user = DBSession.query(User).get('testuser12')
		self.assertEqual(1, user.date_offset)
		self.assertTrue(hasattr(res, 'location'))
		self.assertTrue(res.location.endswith('__FEED__'))

		request = testing.DummyRequest({
			'email': 'testuser@example.com',
			'link_format': 'ignore',
			'days_back': '1',
			'date_offset': '2'
		})
		request.session['user'] = 'testuser12'
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = settings_feed_post(request)
		user = DBSession.query(User).get('testuser12')
		self.assertEqual(2, user.date_offset)
		self.assertTrue(hasattr(res, 'location'))
		self.assertTrue(res.location.endswith('__FEED__'))

		request = testing.DummyRequest({
			'email': 'testuser@example.com',
			'link_format': 'ignore',
			'days_back': '1',
			'date_offset': '3'
		})
		request.session['user'] = 'testuser12'
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = settings_feed_post(request)
		user = DBSession.query(User).get('testuser12')
		self.assertEqual(2, user.date_offset)
		self.assertIn('form_errors', res)
		self.assertIn('date_offset', res.get('form_errors', {}))

		request = testing.DummyRequest({
			'email': 'testuser@example.com',
			'link_format': 'ignore',
			'days_back': '1',
			'date_offset': 'A'
		})
		request.session['user'] = 'testuser12'
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = settings_feed_post(request)
		user = DBSession.query(User).get('testuser12')
		self.assertEqual(2, user.date_offset)
		self.assertIn('form_errors', res)
		self.assertIn('date_offset', res.get('form_errors', {}))

		request = testing.DummyRequest({
			'email': 'testuser@example.com',
			'link_format': 'ignore',
			'days_back': '1'
		})
		request.session['user'] = 'testuser12'
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = settings_feed_post(request)
		user = DBSession.query(User).get('testuser12')
		self.assertEqual(2, user.date_offset)
		self.assertIn('form_errors', res)
		self.assertIn('date_offset', res.get('form_errors', {}))

	def testUpdatePassword(self):

		request = testing.DummyRequest({
			'new': 'asdf',
			'verify': 'asdf'
		})
		request.session['user'] = 'testuser12'
		with self.assertRaises(BadCSRFToken):
			res = password_post(request)

		request = testing.DummyRequest({
			'new': 'asdf',
			'verify': 'asdf'
		})
		request.session['user'] = 'testuser12'
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = password_post(request)
		user = DBSession.query(User).get('testuser12')
		self.assertIn('form_errors', res)
		self.assertIn('current', res.get('form_errors', {}))
		self.assertTrue(user.authenticate('secret'))

		request = testing.DummyRequest({
			'current': 'asdf',
			'verify': 'asdf'
		})
		request.session['user'] = 'testuser12'
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = password_post(request)
		user = DBSession.query(User).get('testuser12')
		self.assertIn('form_errors', res)
		self.assertIn('new', res.get('form_errors', {}))
		self.assertTrue(user.authenticate('secret'))

		request = testing.DummyRequest({
			'current': 'asdf',
			'new': 'asdf'
		})
		request.session['user'] = 'testuser12'
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = password_post(request)
		user = DBSession.query(User).get('testuser12')
		self.assertIn('form_errors', res)
		self.assertIn('verify', res.get('form_errors', {}))
		self.assertTrue(user.authenticate('secret'))

		request = testing.DummyRequest({
			'current': 'asdf',
			'new': 'asdfgh',
			'verify': 'asdfgh'
		})
		request.session['user'] = 'testuser12'
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = password_post(request)
		user = DBSession.query(User).get('testuser12')
		self.assertIn('form_errors', res)
		self.assertIn('current', res.get('form_errors', {}))
		self.assertTrue(user.authenticate('secret'))

		request = testing.DummyRequest({
			'current': 'secret',
			'new': 'asdfg',
			'verify': 'asdfg'
		})
		request.session['user'] = 'testuser12'
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = password_post(request)
		user = DBSession.query(User).get('testuser12')
		self.assertIn('form_errors', res)
		self.assertIn('new', res.get('form_errors', {}))
		self.assertTrue(user.authenticate('secret'))

		request = testing.DummyRequest({
			'current': 'secret',
			'new': 'asdfgh',
			'verify': 'asdfghi'
		})
		request.session['user'] = 'testuser12'
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = password_post(request)
		user = DBSession.query(User).get('testuser12')
		self.assertIn('form_errors', res)
		self.assertIn('verify', res.get('form_errors', {}))
		self.assertTrue(user.authenticate('secret'))

		request = testing.DummyRequest({
			'current': 'secret',
			'new': 'asdfgh',
			'verify': 'asdfgh'
		})
		request.session['user'] = 'testuser12'
		request.params['csrf_token'] = request.session.get_csrf_token()
		res = password_post(request)
		user = DBSession.query(User).get('testuser12')
		self.assertTrue(hasattr(res, 'location'))
		self.assertTrue(res.location.endswith('__PW__'))

	def testResetToken(self):

		request = testing.DummyRequest()
		request.session['user'] = 'testuser12'

		user = DBSession.query(User).get('testuser12')
		token = user.token

		with self.assertRaises(BadCSRFToken):
			res = settings_token_post(request)

		request.params['csrf_token'] = request.session.get_csrf_token()

		res = settings_token_post(request)
		self.assertTrue(hasattr(res, 'location'))
		self.assertTrue(res.location.endswith('__TOKEN__'))
		user = DBSession.query(User).get('testuser12')
		self.assertNotEqual(token, user.token)
		token = user.token

		res = settings_token_post(request)
		self.assertTrue(hasattr(res, 'location'))
		self.assertTrue(res.location.endswith('__TOKEN__'))
		user = DBSession.query(User).get('testuser12')
		self.assertNotEqual(token, user.token)

class TestIndexPage(unittest.TestCase):

	def setUp(self):

		super(TestIndexPage, self).setUp()
		self.config = testing.setUp()
		self.config.add_route('shows', '__SHOWS__')

	def tearDown(self):

		testing.tearDown()

	def test_no_user(self):

		request = testing.DummyRequest()

		res = index(request)
		self.assertFalse(hasattr(res, 'location'))

	def test_user(self):

		request = testing.DummyRequest()
		request.session['user'] = 'testuser1'

		res = index(request)
		self.assertTrue(hasattr(res, 'location'))
		self.assertTrue(res.location.endswith('__SHOWS__'))

class TestMyViewFailureCondition(object):

	def setUp(self):

		super(TestAuthenticationAndAuthorization, self).setUp()
		self.config = testing.setUp()
		engine = create_engine('sqlite://')
		DBSession.configure(bind=engine)

	def tearDown(self):
		DBSession.remove()
		testing.tearDown()

	def test_failing_view(self):
		from .views import my_view
		request = testing.DummyRequest()
		info = my_view(request)
		self.assertEqual(info.status_int, 500)
