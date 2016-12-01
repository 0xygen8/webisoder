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

from decorator import decorator
from deform import Form, ValidationFailure
from datetime import date, timedelta

from pyramid.httpexceptions import HTTPFound, HTTPNotFound, HTTPUnauthorized
from pyramid.httpexceptions import HTTPBadRequest
from pyramid.renderers import render
from pyramid.view import view_config, view_defaults

from pyramid_mailer import get_mailer
from pyramid_mailer.message import Message

from tvdb_api import BaseUI, Tvdb, tvdb_shownotfound

from .models import DBSession, User, Show
from .forms import ProfileForm, PasswordForm, FeedSettingsForm, UnsubscribeForm
from .forms import LoginForm, SearchForm, SignupForm, RequestPasswordResetForm
from .forms import PasswordResetForm

@decorator
def securetoken(func, *args, **kwargs):

	controller = args[0]

	request = controller.request
	uid = request.matchdict.get('user')
	token = request.matchdict.get('token')

	if not uid:
		return HTTPBadRequest()

	user = DBSession.query(User).get(uid)
	if not user:
		return HTTPNotFound()

	if token != user.token:
		return HTTPUnauthorized('Invalid access token.')

	return func(*args, **kwargs)

@view_config(route_name='home', renderer='templates/index.pt', request_method='GET')
def index(request):

	if request.authenticated_userid:
		return HTTPFound(location=request.route_url('shows'))

	return {}

@view_config(route_name='contact', renderer='templates/contact.pt', request_method='GET')
def contact(request):

	return {}

class WebisoderController(object):

	def __init__(self, request):

		self.request = request

	def redirect(self, destination):

		return HTTPFound(location=self.request.route_url(destination))

	def flash(self, level, text):

		self.request.session.flash(text, level)


@view_defaults(renderer='templates/shows.pt', permission='view')
class ShowsController(WebisoderController):

	@view_config(route_name='shows', request_method='GET')
	def get(self):

		uid = self.request.authenticated_userid
		user = DBSession.query(User).get(uid)
		shows = DBSession.query(Show).all()

		return {'subscribed': user.shows, 'shows': shows }

	@view_config(route_name='subscribe', request_method='POST', require_csrf=True)
	def subscribe(self):

		show_id = self.request.POST.get('show')

		if not show_id:
			return { 'error': 'no show specified' }

		if not show_id.isdigit():
			return { 'error': 'illegal show id' }

		show = DBSession.query(Show).get(int(show_id))

		if not show:
			return { 'error': 'no such show' }

		uid = self.request.authenticated_userid
		user = DBSession.query(User).get(uid)
		user.shows.append(show)

		self.flash('info', 'Subscribed to "%s"' % show.name)
		return self.redirect('shows')

	@view_config(route_name='unsubscribe', request_method='POST')
	def unsubscribe(self):

		controls = self.request.POST.items()
		form = Form(UnsubscribeForm())

		try:
			data = form.validate(controls)
		except ValidationFailure:
			self.flash('danger', 'Failed to unsubscribe')
			return self.redirect('shows')

		show_id = data.get('show', 0)
		show = DBSession.query(Show).get(show_id)

		if not show:
			return HTTPNotFound()

		uid = self.request.authenticated_userid
		user = DBSession.query(User).get(uid)
		user.shows.remove(show)

		self.flash('info', 'Unsubscribed from "%s"' % show.name)
		return self.redirect('shows')


@view_defaults(route_name='login', renderer='templates/login.pt')
class AuthController(WebisoderController):

	@view_config(request_method='GET')
	def login_get(self):

		return {}

	@view_config(request_method='POST')
	def login_post(self):

		controls = self.request.POST.items()
		form = Form(LoginForm())

		try:
			data = form.validate(controls)
		except ValidationFailure:
			self.flash('warning', 'Login failed')
			return { 'user': None }

		name = data.get('user')
		password = data.get('password')

		user = DBSession.query(User).get(name)

		if not user:
			self.flash('warning', 'Login failed')
			return { 'user': name }

		if user.authenticate(password):
			self.request.session['auth.userid'] = name
			return self.redirect('shows')

		self.flash('warning', 'Login failed')
		return { 'user': name }

	@view_config(route_name='logout', permission='view')
	def logout(self):

		self.request.session.clear()
		self.flash('info', 'Successfully signed out. Goodbye.')
		return self.redirect('home')


@view_defaults(route_name='register', renderer='templates/register.pt')
class RegistrationController(WebisoderController):

	@view_config(request_method='GET')
	def get(self):

		return {}

	@view_config(request_method='POST')
	def post(self):

		controls = self.request.POST.items()
		form = Form(SignupForm())

		try:
			data = form.validate(controls)
		except ValidationFailure as e:
			errors = e.error.asdict()
			return { 'form_errors': errors }

		name = data.get('name')
		mail = data.get('email')

		if DBSession.query(User).get(name):
			data['form_errors'] = { 'name':
				'This name is already taken' }
			return data
		if DBSession.query(User).filter_by(mail=mail).count() > 0:
			data['form_errors'] = { 'email':
				'This e-mail address is already in use' }
			return data

		user = User(name=name)
		password = user.generate_password()
		user.mail = mail
		DBSession.add(user)

		mailer = get_mailer(self.request)

		body = render(
			'templates/mail/register.pt',
			{ 'name': name, 'password': password },
			request=self.request)
		message = Message(
			subject = "New user registration",
			sender = "noreply@webisoder.net",
			recipients = [ mail ],
			body = body)

		try:
			mailer.send_immediately(message, fail_silently=False)
		except Exception as e:
			DBSession.rollback()
			self.flash("danger", "Failed to send message. Your "
				"account was not created.")
			return { "name": name, "email": mail }

		self.flash('info', 'Your account has been created and your '
			'initial password was sent to %s' % (mail))
		return self.redirect('login')


@view_defaults(route_name="recover", renderer="templates/recover.pt")
class PasswordRecoveryController(WebisoderController):

	@view_config(request_method="GET")
	def get(self):

		return {}

	@view_config(request_method="POST")
	def post(self):

		controls = self.request.POST.items()
		form = Form(RequestPasswordResetForm())

		try:
			data = form.validate(controls)
		except ValidationFailure as e:
			email = self.request.POST.get("email", "")
			errors = e.error.asdict()
			return { "email": email, "form_errors": errors }

		email = data.get("email")
		users = DBSession.query(User).filter_by(mail=email)
		if users.count() != 1:
			data["form_errors"] = { "email": "No such user" }
			return data

		user = users.one()
		user.generate_recover_key()
		mailer = get_mailer(self.request)

		body = render(
			'templates/mail/recover.pt',
			{ "user": user },
			request=self.request)
		message = Message(
			subject = "Webisoder password recovery",
			sender = "noreply@webisoder.net",
			recipients = [ email ],
			body = body)

		try:
			mailer.send_immediately(message, fail_silently=False)
		except Exception as e:
			DBSession.rollback()
			self.flash("danger", "Failed to send message. Your "
				"account was not created.")
			return { "email": email }

		self.flash("info", "Instructions on how to reset your password "
			"have been sent to %s" % ( email ))
		return self.redirect("login")

@view_defaults(route_name="reset_password", renderer="templates/reset.pt")
class PasswordResetController(WebisoderController):

	@view_config(request_method="GET")
	def get(self):

		key = self.request.matchdict.get("key", "")

		if not key:
			raise HTTPBadRequest()

		return { "key": key }

	@view_config(request_method="POST")
	def post(self):

		controls = self.request.POST.items()
		form = Form(PasswordResetForm())
		key = self.request.matchdict.get("key", "")

		try:
			data = form.validate(controls)
		except ValidationFailure as e:
			email = self.request.POST.get("email", "")
			errors = e.error.asdict()

			return {
				"email": email,
				"key": key,
				"form_errors": errors
			}

		email = data.get("email")

		if not data.get("verify") == data.get("password"):

			self.flash("danger", "Password reset failed")
			msg = "Passwords do not match"
			return {
				"email": email,
				"key": key,
				"form_errors": {"verify": msg }
			}

		query = DBSession.query(User).filter_by(mail=email)
		if query.count() != 1:

			self.flash("danger", "Password reset failed")
			msg = "No such user"
			return {
				"email": email,
				"key": key,
				"form_errors": {"email": msg }
			}

		user = query.one()
		if key != user.recover_key:

			msg = "Wrong recovery key"
			return {
				"email": email,
				"key": key,
				"form_errors": {"key": msg }
			}

		user.password = data.get("password")

		self.flash('info', 'Your password has been changed')
		return self.redirect("login")


@view_defaults(route_name='search', permission='view')
class SearchController(WebisoderController):

	@view_config(renderer='templates/search.pt', request_method='POST')
	def post(self, tvdb=Tvdb):

		controls = self.request.POST.items()
		form = Form(SearchForm())

		try:
			data = form.validate(controls)
		except ValidationFailure as e:
			search = self.request.POST.get('search', '')
			errors = e.error.asdict()
			return { 'search': search, 'form_errors': errors }

		result = []
		search = data.get('search')

		class TVDBSearch(BaseUI):
			def selectSeries(self, allSeries):
				result.extend(allSeries)
				return BaseUI.selectSeries(self, allSeries)

		tv = tvdb(custom_ui=TVDBSearch)

		try:
			tv[search]
		except tvdb_shownotfound:
			return { 'search': search }

		return { 'shows': result, 'search': search }


@view_defaults(request_method='GET')
class EpisodesController(WebisoderController):

	def episodes(self, uid):

		# TODO: remove this
		#from .models import Episode

		#s = Show(name='The Big Bang Theory')
		#s.updated = datetime.now()
		#e1 = Episode(show=s, season=1, num=1, airdate=datetime.now())
		#e1.updated = s.updated
		#e2 = Episode(show=s, season=1, num=1, airdate=datetime.now())
		#e2.updated = s.updated
		#e3 = Episode(show=s, season=1, num=1, airdate=datetime.now())
		#e3.updated = s.updated
		#e4 = Episode(show=s, season=1, num=1, airdate=datetime.now())
		#e4.updated = s.updated
		#e5 = Episode(show=s, season=1, num=1, airdate=datetime.now())
		#e5.updated = s.updated
		#episodes = [e1,e2,e3,e4,e5]
		# END

		user = DBSession.query(User).get(uid)
		then = date.today() - timedelta(user.days_back or 0)
		episodes = [e for e in user.episodes if e.airdate >= then]

		return { 'episodes': episodes, 'user': user }

	@view_config(route_name='feed', renderer='templates/feed.pt')
	@view_config(route_name='ical', renderer='templates/ical.pt')
	@view_config(route_name='html', renderer='templates/episodes.pt')
	@securetoken
	def feed(self):

		uid = self.request.matchdict.get('user')
		return self.episodes(uid)

	@view_config(route_name='episodes', renderer='templates/episodes.pt', permission='view')
	def get(self):

		uid = self.request.authenticated_userid
		return self.episodes(uid)


@view_defaults(permission='view', route_name='profile')
class ProfileController(WebisoderController):

	@view_config(renderer='templates/profile.pt', request_method='GET')
	def get(self):

		uid = self.request.authenticated_userid
		user = DBSession.query(User).get(uid)

		return { 'user': user }

	@view_config(renderer='templates/profile.pt', request_method='POST')
	def post(self):

		uid = self.request.authenticated_userid
		user = DBSession.query(User).get(uid)

		controls = self.request.POST.items()
		form = Form(ProfileForm())

		try:
			data = form.validate(controls)
		except ValidationFailure as e:
			self.flash('danger', 'Failed to update profile')
			return { 'user': user, 'form_errors': e.error.asdict() }

		if not user.authenticate(data.get('password')):

			self.flash('danger', 'Password change failed')
			msg = 'Wrong password'
			return {'user': user, 'form_errors': {'password': msg}}

		user.mail = data.get('email', user.mail)
		user.site_news = data.get('site_news', user.site_news)

		self.flash('info', 'Your settings have been updated')
		return self.redirect('profile')

@view_defaults(permission='view', route_name='settings_feed')
class FeedSettingsController(WebisoderController):

	@view_config(renderer='templates/feed_cfg.pt', request_method='GET')
	def get(self):

		uid = self.request.authenticated_userid
		user = DBSession.query(User).get(uid)

		return { 'user': user }

	@view_config(renderer='templates/feed_cfg.pt', request_method='POST')
	def post(self):

		uid = self.request.authenticated_userid
		user = DBSession.query(User).get(uid)

		controls = self.request.POST.items()
		form = Form(FeedSettingsForm())

		try:
			data = form.validate(controls)
		except ValidationFailure as e:
			self.flash('danger', 'Failed to update profile')
			return { 'user': user, 'form_errors': e.error.asdict() }

		user.days_back = data.get('days_back', user.days_back)
		user.date_offset = data.get('date_offset', user.date_offset)
		user.link_format = data.get('link_format', user.link_format)

		self.flash('info', 'Your settings have been updated')
		return self.redirect('settings_feed')

@view_defaults(permission='view', route_name='settings_token')
class TokenResetController(WebisoderController):

	@view_config(renderer='templates/token.pt', request_method='GET')
	def get(self):

		uid = self.request.authenticated_userid
		user = DBSession.query(User).get(uid)

		return { 'user': user }

	@view_config(renderer='templates/token.pt', request_method='POST')
	def post(self):

		uid = self.request.authenticated_userid
		user = DBSession.query(User).get(uid)
		user.reset_token()

		self.flash('info', 'Your token has been reset')
		return self.redirect('settings_token')

@view_defaults(permission='view', route_name='settings_pw')
class PasswordChangeController(WebisoderController):

	@view_config(renderer='templates/settings_pw.pt', request_method='GET')
	def get(self):

		uid = self.request.authenticated_userid
		user = DBSession.query(User).get(uid)

		return { 'user': user }

	@view_config(renderer='templates/settings_pw.pt', request_method='POST')
	def post(self):

		uid = self.request.authenticated_userid
		user = DBSession.query(User).get(uid)

		controls = self.request.POST.items()
		form = Form(PasswordForm())

		try:
			data = form.validate(controls)
		except ValidationFailure as e:
			self.flash('danger', 'Password change failed')
			return { 'user': user, 'form_errors': e.error.asdict() }

		if not user.authenticate(data.get('current')):

			self.flash('danger', 'Password change failed')
			msg = 'Wrong password'
			return { 'user': user, 'form_errors': { 'current': msg } }

		if not data.get('verify') == data.get('new'):

			self.flash('danger', 'Password change failed')
			msg = 'Passwords do not match'
			return { 'user': user, 'form_errors': { 'verify': msg } }

		user.password = data.get('new')

		self.flash('info', 'Your password has been changed')
		return self.redirect('settings_pw')

# TODO remove this
@view_config(route_name='setup', renderer='templates/empty.pt',
							request_method='GET')
def setup(request):

	user = User(name='admin')
	user.password = 'admin'
	DBSession.add(user)

	show = Show(id=1, name='show1', url='http://1')
	DBSession.add(show)
	user.shows.append(show)

	DBSession.add(Show(id=2, name='show2', url='http://2'))
	DBSession.add(Show(id=3, name='show3', url='http://3'))

	return { 'message': 'all done' }

conn_err_msg = """\
Pyramid is having a problem using your SQL database.  The problem
might be caused by one of the following things:

1.  You may need to run the "initialize_webisoder_db" script
    to initialize your database tables.  Check your virtual
    environment's "bin" directory for this script and try to run it.

2.  Your database server may not be running.  Check that the
    database server referred to by the "sqlalchemy.url" setting in
    your "development.ini" file is running.

After you fix the problem, please restart the Pyramid application to
try it again.
"""
