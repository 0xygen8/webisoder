from pyramid.config import Configurator
from sqlalchemy import engine_from_config

from .models import (
	DBSession,
	Base,
)

def main(global_config, **settings):

	""" This function returns a Pyramid WSGI application.
	"""
	engine = engine_from_config(settings, 'sqlalchemy.')
	DBSession.configure(bind=engine)
	Base.metadata.bind = engine
	config = Configurator(settings=settings)
	config.include('pyramid_chameleon')
	config.include("pyramid_beaker")
	config.add_static_view('static', 'static', cache_max_age=3600)
	config.add_route('home', '/')
	config.add_route('login', '/login')
	config.add_route('logout', '/logout')
	config.add_route('shows', '/shows')
	config.add_route('search', '/search')
	config.add_route('subscribe', '/subscribe')
	config.add_route('unsubscribe', '/unsubscribe')
	config.add_route('setup', '/setup') # TODO remove this
	config.scan()
	return config.make_wsgi_app()
