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

from pyramid import testing
from sqlalchemy import create_engine

from .models import DBSession
from .models import Base, Show, Episode, User

from .views import login, logout, shows, subscribe, unsubscribe, search_post
from .views import index

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
			user = User(name='testuser1')
			user.password = 'secret'
			DBSession.add(user)

	def tearDown(self):

		DBSession.remove()
		testing.tearDown()

	def testInvalidUserName(self):

		request = testing.DummyRequest(post={
			'user': 'testuser2',
			'password': 'secret'
		})
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
		res = login(request)
		self.assertNotIn('user', request.session)
		self.assertFalse(hasattr(res, 'location'))

		msg = request.session.pop_flash('warning')
		self.assertEqual(1, len(msg))
		self.assertEqual('Login failed', msg[0])

	def testInvalidPassword(self):

		request = testing.DummyRequest(post={
			'user': 'testuser1',
			'password': 'wrong'
		})
		res = login(request)
		self.assertNotIn('user', request.session)
		self.assertFalse(hasattr(res, 'location'))

		msg = request.session.pop_flash('warning')
		self.assertEqual(1, len(msg))
		self.assertEqual('Login failed', msg[0])

	def testEmptyPassword(self):

		request = testing.DummyRequest(post={
			'user': 'testuser1',
			'password': ''
		})
		res = login(request)
		self.assertNotIn('user', request.session)
		self.assertFalse(hasattr(res, 'location'))

		msg = request.session.pop_flash('warning')
		self.assertEqual(1, len(msg))
		self.assertEqual('Login failed', msg[0])

	def testMissingPassword(self):

		request = testing.DummyRequest(post={
			'user': 'testuser1'
		})
		res = login(request)
		self.assertNotIn('user', request.session)
		self.assertFalse(hasattr(res, 'location'))

		msg = request.session.pop_flash('warning')
		self.assertEqual(1, len(msg))
		self.assertEqual('Login failed', msg[0])

	def testLoginLogout(self):

		request = testing.DummyRequest(post={
			'user': 'testuser1',
			'password': 'secret'
		})
		res = login(request)

		self.assertTrue(hasattr(res, 'location'))
		self.assertTrue(res.location.endswith('__SHOWS__'))

		self.assertIn('user', request.session)
		self.assertEqual('testuser1', request.session['user'])

		msg = request.session.pop_flash('warning')
		self.assertEqual(0, len(msg))

		msg = request.session.pop_flash('info')
		self.assertEqual(1, len(msg))
		self.assertEqual('Login successful. Welcome back, testuser1.',
								msg[0])
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
			DBSession.add(user)

			self.show1 = Show(id=1, name='show1', url='http://1')
			self.show2 = Show(id=2, name='show2', url='http://2')
			self.show3 = Show(id=3, name='show3', url='http://3')
			self.show4 = Show(id=4, name='show4', url='http://4')

			user.shows.append(self.show1)
			user.shows.append(self.show2)
			user.shows.append(self.show3)
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
		res = subscribe(request)
		self.assertEqual(res.get('error'), 'no show specified')

		request = testing.DummyRequest(post={'show': 'a'})
		request.session['user'] = 'testuser1'
		res = subscribe(request)
		self.assertEqual(res.get('error'), 'illegal show id')

		request = testing.DummyRequest(post={'show': '5'})
		request.session['user'] = 'testuser1'
		res = subscribe(request)
		self.assertEqual(res.get('error'), 'no such show')

		request = testing.DummyRequest(post={'show': '4'})
		request.session['user'] = 'testuser1'
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
		res = unsubscribe(request)
		self.assertEqual(res.get('error'), 'no show specified')

		request = testing.DummyRequest(post={'show': 'a'})
		request.session['user'] = 'testuser1'
		res = unsubscribe(request)
		self.assertEqual(res.get('error'), 'illegal show id')

		request = testing.DummyRequest(post={'show': '5'})
		request.session['user'] = 'testuser1'
		res = unsubscribe(request)
		self.assertEqual(res.get('error'), 'no such show')

		request = testing.DummyRequest(post={'show': '3'})
		request.session['user'] = 'testuser1'
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

		request = testing.DummyRequest(post={'bla': 'big bang'})
		request.session['user'] = 'testuser1'
		res = search_post(request)
		self.assertEqual(res.get('error'), 'search term missing')

		request = testing.DummyRequest(post={'search': 'big bang theory'})
		request.session['user'] = 'testuser1'
		res = search_post(request)
		self.assertEqual(len(res.get('shows')), 1)
		self.assertEqual(res.get('search'), 'big bang theory')
		show = res.get('shows')[0]
		self.assertEqual(show.get('id'), 80379)

		request = testing.DummyRequest(post={'search': 'this does not exist'})
		request.session['user'] = 'testuser1'
		res = search_post(request)
		self.assertEqual(len(res.get('shows')), 0)

		request = testing.DummyRequest(post={'search': 'doctor who'})
		request.session['user'] = 'testuser1'
		res = search_post(request)
		self.assertTrue(len(res.get('shows')) > 5)

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
