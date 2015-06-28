from decorator import decorator

from pyramid.httpexceptions import HTTPFound
from pyramid.response import Response
from pyramid.security import remember, forget
from pyramid.view import view_config

from sqlalchemy.exc import DBAPIError

from .models import (
	DBSession,
	MyModel,
	User,
	Show
)

@decorator
def authenticated(func, *args, **kwargs):

	request = args[0]

	if 'user' in request.session:
		return func(*args, **kwargs)
	else:
		return HTTPFound(location='/login')


@view_config(route_name='home', renderer='templates/index.pt')
def my_view(request):
    try:
        one = DBSession.query(MyModel).filter(MyModel.name == 'one').first()
    except DBAPIError:
        return Response(conn_err_msg, content_type='text/plain', status_int=500)
    return {'one': one, 'project': 'webisoder'}

@view_config(route_name='shows', renderer='templates/shows.pt')
@authenticated
def shows(request):

	uid = request.session.get('user')
	user = DBSession.query(User).get(uid)
	return {'shows': user.shows}

@view_config(route_name='shows', renderer='templates/shows.pt')
@authenticated
def subscribe(request):

	show_id = request.POST.get('show')

	if not show_id:
		return { 'error': 'no show specified' }

	if not show_id.isdigit():
		return { 'error': 'illegal show id' }

	show = DBSession.query(Show).get(int(show_id))

	if not show:
		return { 'error': 'no such show' }

	uid = request.session.get('user')
	user = DBSession.query(User).get(uid)
	user.shows.append(show)

	return { 'message': 'successfully subscribed' }

@view_config(route_name='login', renderer='templates/login.pt', request_method='GET')
def login_get(request):
	return { 'message': '' }

@view_config(route_name='login', renderer='templates/login.pt', request_method='POST')
def login(request):

	name = request.POST.get('user')
	password = request.POST.get('password')

	if not name or not password:
		return { 'message': 'login failed' }

	user = DBSession.query(User).get(name)

	if not user:
		return { 'message': 'login failed' }

	if user.authenticate(password):
		request.session['user'] = name
		return { 'message': 'login ok' }
		#return HTTPFound(location='/')

	return { 'message': 'login failed' }

@view_config(route_name='logout', request_method='GET')
def logout(request):

	request.session.clear()
	return HTTPFound(location='/')

@view_config(route_name='setup', renderer='templates/empty.pt', request_method='GET')
def setup(request):

	user = User(name='admin')
	user.password = 'admin'
	DBSession.add(user)

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

