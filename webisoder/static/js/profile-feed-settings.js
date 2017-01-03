"use strict;"

function updateLinkPreview()
{
	var format = $('#inputFormat').val();
	format = format.replace('##SHOW##', 'Frasier');
	format = format.replace('##SEASON##', '1');
	format = format.replace('##SEASON2##', '01');
	format = format.replace('##EPISODE##', '06');
	format = format.replace('##TITLE##', 'The Crucible');

	var link = $('<a>');
	link.attr('href', format);
	link.text(format);

	$('#linkPreviewVal').html(link);
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

function watchRevertButton()
{
	$("#revert").click(function(ev)
	{
		return confirm("This will dicard your custom link format. Are" +
								" you sure?");
	});
	console.log("#revert");
}

$(document).ready(function()
{
	watchFormatChanges();
	updateLinkPreview();
	watchRevertButton();
});
