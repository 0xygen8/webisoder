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

from decorator import decorator
from deform import Form, ValidationFailure
from datetime import date, timedelta, datetime

from pyramid.httpexceptions import HTTPFound, HTTPNotFound, HTTPUnauthorized
from pyramid.httpexceptions import HTTPBadRequest
from pyramid.renderers import render
from pyramid.response import Response
from pyramid.security import remember, forget
from pyramid.session import check_csrf_token
from pyramid.view import view_config

from pyramid_mailer import get_mailer
from pyramid_mailer.message import Message

from sqlalchemy.exc import DBAPIError
from tvdb_api import BaseUI, Tvdb, tvdb_shownotfound

from .models import DBSession, User, Show
from .forms import ProfileForm, PasswordForm, FeedSettingsForm, UnsubscribeForm
from .forms import LoginForm, SearchForm, SignupForm

@decorator
def securetoken(func, *args, **kwargs):

	request = args[0]

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

@view_config(route_name='shows', renderer='templates/shows.pt', request_method='GET', permission='auth')
def shows(request):

	uid = request.authenticated_userid
	user = DBSession.query(User).get(uid)

	return {'subscribed': user.shows, 'shows': DBSession.query(Show).all()}

@view_config(route_name='episodes', renderer='templates/episodes.pt', request_method='GET', permission='auth')
def episodes(request):

	uid = request.authenticated_userid
	user = DBSession.query(User).get(uid)

	then = date.today() - timedelta(user.days_back or 0)
	episodes = [e for e in user.episodes if e.airdate >= then]

	return { 'episodes': episodes, 'user': user }

@view_config(route_name='feed', renderer='templates/feed.pt', request_method='GET')
@view_config(route_name='ical', renderer='templates/ical.pt', request_method='GET')
@view_config(route_name='html', renderer='templates/episodes.pt', request_method='GET')
@securetoken
def feed(request):

	uid = request.matchdict.get('user')
	user = DBSession.query(User).get(uid)

	then = date.today() - timedelta(user.days_back or 0)
	episodes = [e for e in user.episodes if e.airdate >= then]

	# NEW
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

	return { 'episodes': episodes, 'user': user, 'now': datetime.now() }

@view_config(route_name='subscribe', renderer='templates/shows.pt', request_method='POST', permission='auth')
def subscribe(request):

	# Check the CSRF token
	check_csrf_token(request)

	show_id = request.POST.get('show')

	if not show_id:
		return { 'error': 'no show specified' }

	if not show_id.isdigit():
		return { 'error': 'illegal show id' }

	show = DBSession.query(Show).get(int(show_id))

	if not show:
		return { 'error': 'no such show' }

	uid = request.authenticated_userid
	user = DBSession.query(User).get(uid)
	user.shows.append(show)

	session = request.session
	session.flash('Successfully subscribed to "%s"' % show.name, 'info')
	return HTTPFound(location=request.route_url('shows'))

@view_config(route_name='unsubscribe', renderer='templates/shows.pt', request_method='POST', permission='auth')
def unsubscribe(request):

	# Check the CSRF token
	check_csrf_token(request)

	controls = request.POST.items()
	form = Form(UnsubscribeForm())

	try:
		data = form.validate(controls)
	except ValidationFailure as e:
		request.session.flash('Failed to unsubscribe', 'danger')
		return HTTPFound(location=request.route_url('shows'))

	show_id = data.get('show', 0)
	show = DBSession.query(Show).get(show_id)

	if not show:
		return HTTPNotFound()

	session = request.session
	uid = request.authenticated_userid
	user = DBSession.query(User).get(uid)
	user.shows.remove(show)

	session.flash('Successfully unsubscribed from "%s"' % show.name, 'info')
	return HTTPFound(location=request.route_url('shows'))

@view_config(route_name='login', renderer='templates/login.pt', request_method='GET')
def login_get(request):

	return { 'user': None }

@view_config(route_name='login', renderer='templates/login.pt', request_method='POST')
def login(request):

	# Check the CSRF token
	check_csrf_token(request)

	controls = request.POST.items()
	form = Form(LoginForm())

	try:
		data = form.validate(controls)
	except ValidationFailure as e:
		request.session.flash('Login failed', 'warning')
		return { 'user': None }

	name = data.get('user')
	password = data.get('password')

	user = DBSession.query(User).get(name)

	if not user:
		request.session.flash('Login failed', 'warning')
		return { 'user': name }

	if user.authenticate(password):
		request.session['auth.userid'] = name
		return HTTPFound(location=request.route_url('shows'))

	request.session.flash('Login failed', 'warning')
	return { 'user': name }

@view_config(route_name='signup', renderer='templates/signup.pt', request_method='GET')
def signup(request):

	return {}

@view_config(route_name='signup', renderer='templates/signup.pt', request_method='POST')
def signup_post(request):

	controls = request.POST.items()
	form = Form(SignupForm())

	try:
		data = form.validate(controls)
	except ValidationFailure as e:
		errors = e.error.asdict()
		return { 'form_errors': errors }

	name = data.get('name')
	mail = data.get('email')

	if DBSession.query(User).get(name):
		data['form_errors'] = { 'name': 'This name is already taken' }
		return data
	if DBSession.query(User).filter_by(mail=mail).count() > 0:
		data['form_errors'] = { 'email':
			'A user with this e-mail address already exists' }
		return data

	user = User(name=name)
	password = user.generate_password()
	user.mail = mail
	DBSession.add(user)

	mailer = get_mailer(request)

	body=render('templates/mail/signup.pt',
		{ 'name': name, 'password': password }, request=request )
	message = Message(subject='New user registration',
		sender='noreply@webisoder.net', recipients=[mail],
		body=body)

	mailer.send(message)

	return {}

@view_config(route_name='search', renderer='templates/search.pt', request_method='POST', permission='auth')
def search_post(request, tvdb=Tvdb):

	controls = request.POST.items()
	form = Form(SearchForm())

	try:
		data = form.validate(controls)
	except ValidationFailure as e:
		search = request.POST.get('search', '')
		errors = e.error.asdict()
		return { 'search': search, 'form_errors': errors, 'shows': [] }

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
		return { 'shows': [], 'search': search }

	return { 'shows': result, 'search': search }

@view_config(route_name='logout', request_method='GET', permission='auth')
def logout(request):

	request.session.clear()
	request.session.flash('Successfully signed out. Goodbye.', 'info')
	return HTTPFound(location=request.route_url('home'))

@view_config(route_name='profile', renderer='templates/profile.pt', request_method='GET', permission='auth')
def profile_get(request):

	uid = request.authenticated_userid
	user = DBSession.query(User).get(uid)

	return { 'user': user }

@view_config(route_name='profile', renderer='templates/profile.pt', request_method='POST', permission='auth')
def profile_post(request):

	# Check the CSRF token
	check_csrf_token(request)

	uid = request.authenticated_userid
	user = DBSession.query(User).get(uid)

	controls = request.POST.items()
	form = Form(ProfileForm())

	try:
		data = form.validate(controls)
	except ValidationFailure as e:
		request.session.flash('Failed to update profile', 'danger')
		return { 'user': user, 'form_errors': e.error.asdict() }

	if not user.authenticate(data.get('password')):

		request.session.flash('Password change failed', 'danger')
		msg = 'Wrong password'
		return { 'user': user, 'form_errors': { 'password': msg } }

	user.mail = data.get('email', user.mail)
	user.site_news = data.get('site_news', user.site_news)

	request.session.flash('Your settings have been updated', 'info')
	return HTTPFound(location=request.route_url('profile'))

@view_config(route_name='settings_feed', renderer='templates/settings_feed.pt', request_method='GET', permission='auth')
def settings_feed_get(request):

	uid = request.authenticated_userid
	user = DBSession.query(User).get(uid)

	return { 'user': user }

@view_config(route_name='settings_feed', renderer='templates/settings_feed.pt', request_method='POST', permission='auth')
def settings_feed_post(request):

	# Check the CSRF token
	check_csrf_token(request)

	uid = request.authenticated_userid
	user = DBSession.query(User).get(uid)

	controls = request.POST.items()
	form = Form(FeedSettingsForm())

	try:
		data = form.validate(controls)
	except ValidationFailure as e:
		request.session.flash('Failed to update profile', 'danger')
		return { 'user': user, 'form_errors': e.error.asdict() }

	user.days_back = data.get('days_back', user.days_back)
	user.date_offset = data.get('date_offset', user.date_offset)
	user.link_format = data.get('link_format', user.link_format)

	request.session.flash('Your settings have been updated', 'info')
	return HTTPFound(location=request.route_url('settings_feed'))

@view_config(route_name='settings_token', renderer='templates/settings_token.pt', request_method='GET', permission='auth')
def settings_token_get(request):

	uid = request.authenticated_userid
	user = DBSession.query(User).get(uid)

	return { 'user': user }

@view_config(route_name='settings_token', renderer='templates/settings_token.pt', request_method='POST', permission='auth')
def settings_token_post(request):

	# Check the CSRF token
	check_csrf_token(request)

	uid = request.authenticated_userid
	user = DBSession.query(User).get(uid)
	user.reset_token()

	request.session.flash('Your token has been reset', 'info')
	return HTTPFound(location=request.route_url('settings_token'))

@view_config(route_name='settings_pw', renderer='templates/settings_pw.pt', request_method='GET', permission='auth')
def settings_pw_get(request):

	uid = request.authenticated_userid
	user = DBSession.query(User).get(uid)

	return { 'user': user }

@view_config(route_name='settings_pw', renderer='templates/settings_pw.pt', request_method='POST', permission='auth')
def password_post(request):

	# Check the CSRF token
	check_csrf_token(request)

	uid = request.authenticated_userid
	user = DBSession.query(User).get(uid)

	controls = request.POST.items()
	form = Form(PasswordForm())

	try:
		data = form.validate(controls)
	except ValidationFailure as e:
		request.session.flash('Password change failed', 'danger')
		return { 'user': user, 'form_errors': e.error.asdict() }

	if not user.authenticate(data.get('current')):

		request.session.flash('Password change failed', 'danger')
		msg = 'Wrong password'
		return { 'user': user, 'form_errors': { 'current': msg } }

	if not data.get('verify') == data.get('new'):

		request.session.flash('Password change failed', 'danger')
		msg = 'Passwords to not match'
		return { 'user': user, 'form_errors': { 'verify': msg } }

	user.password = data.get('new')

	request.session.flash('Your password has been changed', 'info')
	return HTTPFound(location=request.route_url('settings_pw'))

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

