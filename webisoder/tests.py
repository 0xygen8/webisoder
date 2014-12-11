import unittest
import transaction

from pyramid import testing

from .models import DBSession
from .models import Base, Show, Episode, User

class WebisoderModelTests(unittest.TestCase):

	def setUp(self):

		self.config = testing.setUp()
		from sqlalchemy import create_engine
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

		self.assertEqual(0, user1.episodes.count())
		self.assertEqual(2, user2.episodes.count())
		self.assertEqual(3, user3.episodes.count())

		self.assertIn(s1e1, user2.episodes.all())
		self.assertIn(s1e2, user2.episodes.all())

		self.assertIn(s1e1, user3.episodes.all())
		self.assertIn(s1e2, user3.episodes.all())
		self.assertIn(s2e1, user3.episodes.all())

		user3.shows.remove(show1)
		self.assertEqual(1, user3.episodes.count())

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

class TestMyViewSuccessCondition(unittest.TestCase):
    def setUp(self):
        self.config = testing.setUp()
        from sqlalchemy import create_engine
        engine = create_engine('sqlite://')
        from .models import (
            Base,
            MyModel,
            )
        DBSession.configure(bind=engine)
        Base.metadata.create_all(engine)
        with transaction.manager:
            model = MyModel(name='one', value=55)
            DBSession.add(model)

    def tearDown(self):
        DBSession.remove()
        testing.tearDown()

    def test_passing_view(self):
        from .views import my_view
        request = testing.DummyRequest()
        info = my_view(request)
        self.assertEqual(info['one'].name, 'one')
        self.assertEqual(info['project'], 'webisoder')


class TestMyViewFailureCondition(unittest.TestCase):
    def setUp(self):
        self.config = testing.setUp()
        from sqlalchemy import create_engine
        engine = create_engine('sqlite://')
        from .models import (
            Base,
            MyModel,
            )
        DBSession.configure(bind=engine)

    def tearDown(self):
        DBSession.remove()
        testing.tearDown()

    def test_failing_view(self):
        from .views import my_view
        request = testing.DummyRequest()
        info = my_view(request)
        self.assertEqual(info.status_int, 500)
