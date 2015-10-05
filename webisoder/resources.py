from pyramid.security import Allow, Authenticated

class Root(object):

	__acl__ = [
		(Allow, Authenticated, 'auth'),
		(Allow, 'Token', 'token')
	]

	def __init__(self, request):
		pass
