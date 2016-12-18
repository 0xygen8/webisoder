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


class LoginFailure(Exception):

	pass


class MailError(Exception):

	def __init__(self, error):

		self.error = error

	def __str__(self):

		return str(self.error)


class SubscriptionFailure(Exception):

	pass


class FormError(Exception):

	def __init__(self, vals):

		self.vals = vals

	def __get_self(self):

		return self

	def asdict(self):

		return self.vals

	error = property(__get_self)


class DuplicateUserName(FormError):

	def __init__(self):

		msg = "This name is already taken"
		super(DuplicateUserName, self).__init__({"name": msg})


class DuplicateEmail(FormError):

	def __init__(self):

		msg = "This e-mail address is already in use"
		super(DuplicateEmail, self).__init__({"email": msg})
