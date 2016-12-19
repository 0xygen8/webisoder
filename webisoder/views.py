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

import logging
import httplib

from decorator import decorator
from deform import Form, ValidationFailure
from datetime import date, timedelta
from beaker.cache import cache_region
from urllib2 import urlopen, Request

from pyramid.httpexceptions import HTTPFound, HTTPBadRequest, HTTPUnauthorized
from pyramid.httpexceptions import HTTPNotFound
from pyramid.response import Response
from pyramid.security import remember, forget
from pyramid.view import view_config, view_defaults

from tvdb_api import BaseUI, Tvdb, tvdb_shownotfound, tvdb_error

from .models import DBSession, User, Show
from .errors import LoginFailure, MailError, SubscriptionFailure, DuplicateEmail
from .errors import FormError, DuplicateUserName
from .forms import LoginForm, PasswordResetForm, FeedSettingsForm, SubscribeForm
from .forms import ProfileForm, SearchForm, SignupForm, RequestPasswordResetForm
from .forms import PasswordForm, UnSubscribeForm
from .mail import WelcomeMessage, PasswordRecoveryMessage

log = logging.getLogger(__name__)


class TVDBWrapper(object):

	def getByURL(self, url):

		if not url.isdigit():
			raise tvdb_shownotfound()

		tv = Tvdb()
		return tv[int(url)]

	@cache_region("month")
	def downloadBanner(self, url):

		req = Request(url)
		res = urlopen(req)
		return res.read()

	@cache_region("week")
	def getBanner(self, url):

		best = None
		best_rating = 0

		if not url.isdigit():
			raise tvdb_shownotfound()

		tv = Tvdb(banners = True)
		show = tv[int(url)]

		banners = show["_banners"]
		fanart = banners.get("fanart")

		for res in fanart:
			items = fanart.get(res)

			for id in items:
				item = items.get(id)
				path = item.get("_thumbnailpath")
				rating = float(item.get("rating", 0))

				if rating > best_rating:
					best = path

		return self.downloadBanner(best)

	def search(self, text):

		result = []

		class TVDBSearch(BaseUI):
			def selectSeries(self, allSeries):
				result.extend(allSeries)
				return BaseUI.selectSeries(self, allSeries)

		tv = Tvdb(custom_ui=TVDBSearch)
		tv[text]

		return result

@decorator
def securetoken(func, *args, **kwargs):

	controller = args[0]

	request = controller.request
	uid = request.matchdict.get("user")
	token = request.matchdict.get("token")

	if not uid:
		return HTTPBadRequest()

	user = DBSession.query(User).get(uid)
	if not user:
		return HTTPNotFound()

	if token != user.token:
		return HTTPUnauthorized("Invalid access token.")

	return func(*args, **kwargs)


class WebisoderController(object):

	def __init__(self, request):

		self.request = request

	def redirect(self, destination):

		return HTTPFound(location=self.request.route_url(destination))

	def flash(self, level, text):

		self.request.session.flash(text, level)


@view_defaults(renderer="templates/index.pt")
class IndexController(WebisoderController):

	@view_config(route_name="home", request_method="GET")
	def get(self):

		if self.request.authenticated_userid:
			return self.redirect("shows")

		return {}


@view_defaults(renderer="templates/contact.pt")
class ContactsController(WebisoderController):

	@view_config(route_name="contact", request_method="GET")
	def get(self):

		return {}


@view_defaults(renderer="templates/shows.pt")
class ShowsController(WebisoderController):

	def __init__(self, request):

		super(ShowsController, self).__init__(request)
		self.backend = TVDBWrapper

	@view_config(route_name="shows", request_method="GET",
							permission="view")
	def get(self):

		uid = self.request.authenticated_userid
		user = DBSession.query(User).get(uid)

		return {"subscribed": user.shows }

	@view_config(context=ValidationFailure)
	@view_config(context=SubscriptionFailure)
	def failure(self):

		self.flash("danger", "Failed to modify subscription")

		uid = self.request.authenticated_userid
		user = DBSession.query(User).get(uid)

		res = self.request.POST
		res["subscribed"] = user.shows

		return res

	@view_config(context=tvdb_shownotfound)
	def tvdb_not_found(self):

		log.critical("TVDB subscription failed: Show not found")
		self.flash("danger", "Failed to subscribe to show: not found")

		uid = self.request.authenticated_userid
		user = DBSession.query(User).get(uid)

		res = self.request.POST
		res["subscribed"] = user.shows

		return res

	def import_show(self, url):

		engine = self.backend()
		data = engine.getByURL(url)
		show = Show()
		show.url = url
		show.name = data["seriesname"]

		DBSession.add(show)

	@view_config(route_name="subscribe", request_method="POST",
							permission="view")
	def subscribe(self):

		controls = self.request.POST.items()
		form = Form(SubscribeForm())
		data = form.validate(controls)

		url = data.get("url")
		query = DBSession.query(Show).filter_by(url=url)

		if query.count() != 1:
			self.import_show(url)

		show = query.one()
		uid = self.request.authenticated_userid
		user = DBSession.query(User).get(uid)
		user.shows.append(show)

		self.flash("info", 'Subscribed to "%s"' % show.name)
		return self.redirect("shows")

	@view_config(route_name="unsubscribe", request_method="POST",
							permission="view")
	def unsubscribe(self):

		controls = self.request.POST.items()
		form = Form(UnSubscribeForm())
		data = form.validate(controls)

		show_id = data.get("show")
		show = DBSession.query(Show).get(show_id)

		if not show:
			raise SubscriptionFailure()

		uid = self.request.authenticated_userid
		user = DBSession.query(User).get(uid)
		user.shows.remove(show)

		self.flash("info", 'Unsubscribed from "%s"' % show.name)
		return self.redirect("shows")


@view_defaults(route_name="login", renderer="templates/login.pt")
class AuthController(WebisoderController):

	@view_config(request_method="GET")
	def login_get(self):

		return {}

	@view_config(context=ValidationFailure)
	@view_config(context=LoginFailure)
	def failure(self):

		log.warning("Failed login from %s" % self.request.remote_addr)

		self.flash("warning", "Login failed")
		return self.request.POST

	@view_config(request_method="POST")
	def login_post(self):

		controls = self.request.POST.items()
		form = Form(LoginForm())
		data = form.validate(controls)

		name = data.get("user")
		password = data.get("password")

		user = DBSession.query(User).get(name)

		if not user:
			raise LoginFailure()

		if not user.authenticate(password):
			raise LoginFailure()

		# Create new sessions for authenticated users
		self.request.session.invalidate()

		remember(self.request, name)
		return self.redirect("shows")

	@view_config(route_name="logout", permission="view")
	def logout(self):

		forget(self.request)
		return self.redirect("home")


@view_defaults(route_name="register", renderer="templates/register.pt")
class RegistrationController(WebisoderController):

	@view_config(request_method="GET")
	def get(self):

		return {}

	@view_config(context=ValidationFailure)
	@view_config(context=FormError)
	def failure(self):

		e = self.request.exception

		res = self.request.POST
		res["form_errors"] = e.error.asdict()
		return res

	@view_config(context=MailError)
	def smtp_failure(self):

		log.critical("SMTP failure: %s" % self.request.exception)

		DBSession.rollback()
		self.flash("danger", "Failed to send message. Your account was "
								"not created.")
		res = self.request.POST
		return res

	@view_config(request_method="POST")
	def post(self):

		controls = self.request.POST.items()
		form = Form(SignupForm())
		data = form.validate(controls)

		name = data.get("name")
		mail = data.get("email")

		if DBSession.query(User).get(name):
			raise DuplicateUserName()
		if DBSession.query(User).filter_by(mail=mail).count() > 0:
			raise DuplicateEmail()

		user = User(name=name)
		password = user.generate_password()
		user.mail = mail
		DBSession.add(user)

		msg = WelcomeMessage()
		msg.send(self.request, user, password)

		self.flash("info", "Your account has been created and your "
				"initial password was sent to %s" % (mail))
		return self.redirect("login")


@view_defaults(route_name="recover", renderer="templates/recover.pt")
class PasswordRecoveryController(WebisoderController):

	@view_config(request_method="GET")
	def get(self):

		return {}

	@view_config(context=ValidationFailure)
	@view_config(context=FormError)
	def failure(self):

		e = self.request.exception

		res = self.request.POST
		res["form_errors"] = e.error.asdict()
		return res

	@view_config(context=MailError)
	def smtp_failure(self):

		log.critical("SMTP failure: %s" % self.request.exception)

		DBSession.rollback()
		self.flash("danger", "Failed to send message. Your password "
							"was not reset.")
		res = self.request.POST
		return res

	@view_config(request_method="POST")
	def post(self):

		controls = self.request.POST.items()
		form = Form(RequestPasswordResetForm())
		data = form.validate(controls)

		email = data.get("email")
		users = DBSession.query(User).filter_by(mail=email)

		if users.count() != 1:
			raise FormError({"email": "No such user"})

		user = users.one()
		user.generate_recover_key()

		msg = PasswordRecoveryMessage()
		msg.send(self.request, user)

		self.flash("info", "Instructions on how to reset your password "
					"have been sent to %s" % (email))
		return self.redirect("login")


@view_defaults(route_name="reset_password", renderer="templates/reset.pt")
class PasswordResetController(WebisoderController):

	@view_config(request_method="GET")
	def get(self):

		key = self.request.matchdict.get("key")

		if not key:
			raise HTTPBadRequest()

		return { "key": key }

	@view_config(context=ValidationFailure)
	@view_config(context=FormError)
	def failure(self):

		e = self.request.exception

		res = self.request.POST
		res["key"] = self.request.matchdict.get("key")
		res["form_errors"] = e.error.asdict()
		return res

	@view_config(request_method="POST")
	def post(self):

		controls = self.request.POST.items()
		form = Form(PasswordResetForm())
		key = self.request.matchdict.get("key")
		data = form.validate(controls)

		email = data.get("email")

		if data.get("verify") != data.get("password"):
			raise FormError({"verify": "Passwords do not match"})

		query = DBSession.query(User).filter_by(mail=email)
		if query.count() != 1:
			raise FormError({"email": "No such user"})

		user = query.one()
		if not key or key != user.recover_key:
			raise FormError({"key": "Wrong recovery key"})

		user.password = data.get("password")

		self.flash("info", "Your password has been changed")
		return self.redirect("login")


@view_defaults(route_name="search", renderer="templates/search.pt")
class SearchController(WebisoderController):

	def __init__(self, request):

		super(SearchController, self).__init__(request)
		self.backend = TVDBWrapper

	@view_config(context=ValidationFailure)
	def failure(self):

		e = self.request.exception

		res = self.request.POST
		res["form_errors"] = e.error.asdict()
		return res

	@view_config(context=tvdb_shownotfound)
	def not_found(self):

		res = self.request.POST
		res["shows"] = []
		return res

	@view_config(context=tvdb_error)
	@view_config(context=httplib.IncompleteRead)
	def tvdb_failure(self):

		self.flash("danger", "Failed to reach TheTVDB, search results "
			"will be incomplete.")

		log.critical("TVDB failure: %s" % self.request.exception)

		res = self.request.POST
		res["shows"] = []
		return res

	@view_config(request_method="POST", permission="view")
	def post(self):

		controls = self.request.POST.items()
		form = Form(SearchForm())
		data = form.validate(controls)

		search = data.get("search")

		engine = self.backend()
		result = engine.search(search)

		return { "shows": result, "search": search }


@view_defaults(request_method="GET")
class EpisodesController(WebisoderController):

	def episodes(self, uid):

		user = DBSession.query(User).get(uid)
		then = date.today() - timedelta(int(user.days_back) or 0)

		episodes = [e for e in user.episodes if e.airdate >= then]

		return {
			"episodes": sorted(episodes, key=lambda ep: ep.airdate),
			"user": user
		}

	@view_config(route_name="feed", renderer="templates/feed.pt")
	@view_config(route_name="ical", renderer="templates/ical.pt")
	@view_config(route_name="html", renderer="templates/episodes.pt")
	@securetoken
	def feed(self):

		uid = self.request.matchdict.get("user")
		return self.episodes(uid)

	@view_config(route_name="episodes", renderer="templates/episodes.pt",
							permission="view")
	def get(self):

		uid = self.request.authenticated_userid
		return self.episodes(uid)


@view_defaults(route_name="profile", renderer="templates/profile.pt")
class ProfileController(WebisoderController):

	@view_config(permission="view", request_method="GET")
	def get(self):

		uid = self.request.authenticated_userid
		user = DBSession.query(User).get(uid)

		return { "user": user }

	@view_config(context=ValidationFailure)
	@view_config(context=FormError)
	def failure(self):

		e = self.request.exception
		uid = self.request.authenticated_userid

		self.flash("danger", "Failed to update profile")

		res = self.request.POST
		res["form_errors"] = e.error.asdict()
		res["user"] = DBSession.query(User).get(uid)
		return res

	@view_config(permission="view", request_method="POST")
	def post(self):

		uid = self.request.authenticated_userid
		user = DBSession.query(User).get(uid)

		controls = self.request.POST.items()
		form = Form(ProfileForm())
		data = form.validate(controls)

		if not user.authenticate(data.get("password")):
			raise FormError({"password": "Wrong password"})

		user.mail = data.get("email", user.mail)
		user.site_news = data.get("site_news", user.site_news)

		self.flash("info", "Your settings have been updated")
		return self.redirect("profile")


@view_defaults(route_name="settings_feed", renderer="templates/feed_cfg.pt")
class FeedSettingsController(WebisoderController):

	@view_config(permission="view", request_method="GET")
	def get(self):

		uid = self.request.authenticated_userid
		user = DBSession.query(User).get(uid)

		return { "user": user }

	@view_config(context=ValidationFailure)
	@view_config(context=FormError)
	def failure(self):

		e = self.request.exception
		uid = self.request.authenticated_userid

		self.flash("danger", "Failed to update profile")

		res = self.request.POST
		res["form_errors"] = e.error.asdict()
		res["user"] = DBSession.query(User).get(uid)
		return res

	@view_config(permission="view", request_method="POST")
	def post(self):

		uid = self.request.authenticated_userid
		user = DBSession.query(User).get(uid)

		controls = self.request.POST.items()
		form = Form(FeedSettingsForm())
		data = form.validate(controls)

		user.days_back = data.get("days_back", user.days_back)
		user.date_offset = data.get("date_offset", user.date_offset)
		user.link_format = data.get("link_format", user.link_format)

		self.flash("info", "Your settings have been updated")
		return self.redirect("settings_feed")


@view_defaults(route_name="settings_token", renderer="templates/token.pt")
class TokenResetController(WebisoderController):

	@view_config(permission="view", request_method="GET")
	def get(self):

		uid = self.request.authenticated_userid
		user = DBSession.query(User).get(uid)

		return { "user": user }

	@view_config(permission="view", request_method="POST")
	def post(self):

		uid = self.request.authenticated_userid
		user = DBSession.query(User).get(uid)
		user.reset_token()

		self.flash("info", "Your token has been reset")
		return self.redirect("settings_token")


@view_defaults(route_name="settings_pw", renderer="templates/settings_pw.pt")
class PasswordChangeController(WebisoderController):

	@view_config(permission="view", request_method="GET")
	def get(self):

		uid = self.request.authenticated_userid
		user = DBSession.query(User).get(uid)

		return { "user": user }

	@view_config(context=ValidationFailure)
	@view_config(context=FormError)
	def failure(self):

		e = self.request.exception
		uid = self.request.authenticated_userid

		self.flash("danger", "Password change failed")

		res = self.request.POST
		res["form_errors"] = e.error.asdict()
		res["user"] = DBSession.query(User).get(uid)
		return res

	@view_config(permission="view", request_method="POST")
	def post(self):

		uid = self.request.authenticated_userid
		user = DBSession.query(User).get(uid)

		controls = self.request.POST.items()
		form = Form(PasswordForm())
		data = form.validate(controls)

		if not user.authenticate(data.get("current")):
			raise FormError({"current": "Wrong password"})

		if not data.get("verify") == data.get("new"):
			raise FormError({"verify": "Passwords do not match"})

		user.password = data.get("new")

		self.flash("info", "Your password has been changed")
		return self.redirect("settings_pw")


@view_defaults(route_name="banners", http_cache=3600)
class BannerController(WebisoderController):

	def __init__(self, request):

		super(BannerController, self).__init__(request)
		self.backend = TVDBWrapper

	@view_config(permission="view", request_method="GET")
	def get(self):

		show_id = self.request.matchdict.get("show_id")

		engine = self.backend()

		res = Response(body=engine.getBanner(show_id))
		res.content_type = "image/jpeg"
		return res

# TODO remove this
@view_config(route_name="setup", renderer="templates/empty.pt",
							request_method="GET")
def setup(request):

	user = User(name="admin")
	user.password = "admin"
	DBSession.add(user)

	from datetime import datetime
	from .models import Episode

	show = Show(id=1, name="show1", url="http://1")
	show.updated = datetime.now()
	DBSession.add(show)
	user.shows.append(show)

	DBSession.add(Show(id=2, name="show2", url="http://2"))
	DBSession.add(Show(id=3, name="show3", url="http://3"))

	episode = Episode(show=show, season=1, num=1, airdate=datetime.now())
	episode.updated = show.updated
	show.episodes.append(episode)

	episode = Episode(show=show, season=1, num=2, airdate=datetime.now())
	episode.updated = show.updated
	show.episodes.append(episode)

	episode = Episode(show=show, season=1, num=3, airdate=datetime.now())
	episode.updated = show.updated
	show.episodes.append(episode)

	episode = Episode(show=show, season=1, num=4, airdate=datetime.now())
	episode.updated = show.updated
	show.episodes.append(episode)

	episode = Episode(show=show, season=1, num=5, airdate=datetime.now())
	episode.updated = show.updated
	show.episodes.append(episode)

	return { "message": "all done" }
