$(document).ready(function() {
	$("#1").click(function(){
	   	 $("#from-device-a").toggle();
	   	 $("#to-device-a").toggle();
	});

	$("#show-all-logs").click(function(){
   	 	$("#all-packets").toggle();
	});
});