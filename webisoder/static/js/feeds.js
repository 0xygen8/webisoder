"use strict;"

$(document).ready(function()
{
	$('#resetTokenForm').submit(function(ev)
	{
		return confirm('This will invalidate all your current feeds ' +
			'and calendars. Are you sure you want to proceed?');
	});
});
