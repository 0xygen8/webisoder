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

from pyramid.renderers import render

from pyramid_mailer import get_mailer
from pyramid_mailer.message import Message

from .errors import MailError

class WelcomeMessage(object):

	def send(self, request, to, password):

		mailer = get_mailer(request)

		body = render("templates/mail/register.pt",
			{ "name": to.name, "password": password },
			request=request)

		message = Message(
			subject = "New user registration",
			sender = "noreply@webisoder.net",
			recipients = [ to.mail ],
			body = body)

		try:
			mailer.send_immediately(message, fail_silently=False)
		except Exception as e:
			raise MailError(e)


class PasswordRecoveryMessage(object):

	def send(self, request, to):

		mailer = get_mailer(request)

		body = render("templates/mail/recover.pt",
			{ "user": to }, request=request)
		message = Message(
			subject = "Webisoder password recovery",
			sender = "noreply@webisoder.net",
			recipients = [ to.mail ],
			body = body)

		try:
			mailer.send_immediately(message, fail_silently=False)
		except Exception as e:
			raise MailError(e)
