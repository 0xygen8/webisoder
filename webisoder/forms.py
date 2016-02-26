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

from colander import null, Invalid, MappingSchema, SchemaNode, Email, Range
from colander import Length, String, Integer

# colander.Boolean should behave like this but does not
class Boolean(object):

	def serialize(self, node, val):

		if val is null:
			return null
		if not isinstance(val, bool):
			raise Invalid(node, '%r is not a boolean')
		return val and 'true' or 'false'

	def deserialize(self, node, data):

		if data is null:
			return False
		if not isinstance(data, basestring):
			raise Invalid(node, '%r is not a string' % data)
		value = data.lower()
		if value in ('true', 'yes', 'y', 'on', 't', '1'):
			return True

		return False

class ProfileForm(MappingSchema):

	email = SchemaNode(String(), validator=Email())
	site_news = SchemaNode(Boolean())
	password = SchemaNode(String())

class FeedSettingsForm(MappingSchema):

	days_back = SchemaNode(Integer(), validator=Range(1, 7))
	date_offset = SchemaNode(Integer(), validator=Range(0, 2))
	link_format = SchemaNode(String(), validator=Length(min=6))

class PasswordForm(MappingSchema):

	current = SchemaNode(String())
	new = SchemaNode(String(), validator=Length(min=6))
	verify = SchemaNode(String())

class UnsubscribeForm(MappingSchema):

	show = SchemaNode(Integer())

class LoginForm(MappingSchema):

	user = SchemaNode(String())
	password = SchemaNode(String())

class SignupForm(MappingSchema):

	name = SchemaNode(String())
	email = SchemaNode(String(), validator=Email())

class SearchForm(MappingSchema):

	search = SchemaNode(String(), validator=Length(min=3))
