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

from pyramid.config import Configurator
from sqlalchemy import engine_from_config

from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.authentication import SessionAuthenticationPolicy
from pyramid.httpexceptions import HTTPFound

from .models import DBSession, Base

def redirect_login(request):

	return HTTPFound(location=request.route_url('login'))

def main(global_config, **settings):

	""" This function returns a Pyramid WSGI application.
	"""
	engine = engine_from_config(settings, 'sqlalchemy.')
	DBSession.configure(bind=engine)
	Base.metadata.bind = engine
	config = Configurator(settings=settings, root_factory='.resources.Root')

	authentication_policy = SessionAuthenticationPolicy()
	authorization_policy = ACLAuthorizationPolicy()

	config.set_authentication_policy(authentication_policy)
	config.set_authorization_policy(authorization_policy)
	config.add_forbidden_view(redirect_login)
	config.include('pyramid_chameleon')
	config.include("pyramid_beaker")
	config.add_static_view('static', 'static', cache_max_age=3600)
	config.add_route('home', '/')
	config.add_route('login', '/login')
	config.add_route('logout', '/logout')
	config.add_route('shows', '/shows')
	config.add_route('search', '/search')
	config.add_route('profile', '/profile')
	config.add_route('settings_feed', '/settings/feeds')
	config.add_route('settings_pw', '/settings/password')
	config.add_route('settings_token', '/settings/token')
	config.add_route('episodes', '/episodes')
	config.add_route('feed', '/atom/{user}/{token}')
	config.add_route('ical', '/ical/{user}/{token}')
	config.add_route('html', '/episodes/{user}/{token}')
	config.add_route('subscribe', '/subscribe')
	config.add_route('unsubscribe', '/unsubscribe')
	config.add_route('setup', '/setup') # TODO remove this
	config.scan()
	return config.make_wsgi_app()
