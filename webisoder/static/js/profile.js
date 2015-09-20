"use strict;"

function updateLinkPreview()
{
	var format = $('#inputFormat').val();
	format = format.replace('##SHOW##', 'Frasier');
	format = format.replace('##SEASON##', '1');
	format = format.replace('##SEASON2##', '01');
	format = format.replace('##EPISODE##', '06');
	format = format.replace('##TITLE##', 'The Crucible');

	$('#linkPreviewVal').html('<a href="' + format + '">' + format + '</a>');
}

function watchFormatChanges()
{
	$('#linkPreview').show();
	$('#inputFormat').keyup(function(ev)
	{
		updateLinkPreview();
	});
	$('#inputFormat').change(function(ev)
	{
		updateLinkPreview();
	});
}

function watchTokenForm()
{
	$('#resetTokenForm').submit(function(ev)
	{
		return confirm('This will invalidate all your current feeds ' +
			'and calendars. Are you sure you want to proceed?');
	});
}

$(document).ready(function()
{
	watchFormatChanges();
	updateLinkPreview();
	watchTokenForm();
});
