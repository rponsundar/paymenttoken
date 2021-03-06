function getParameterByName(name) {
	name = name.replace(/[\[]/, "\\[").replace(/[\]]/, "\\]");
	var regex = new RegExp("[\\?&]" + name + "=([^&#]*)"), results = regex
			.exec(location.search);
	return results === null ? "" : decodeURIComponent(results[1].replace(/\+/g,
			" "));
}
if (localStorage.getItem("urnlocal") === ""
		|| !localStorage.getItem("urnlocal")) {
	var urn = getParameterByName('urn');
	localStorage.setItem("urnlocal", urn);
}
if (localStorage.getItem("translocal") === ""
	|| !localStorage.getItem("translocal")) {
var transactionDetails = getParameterByName('transactionDetails');
localStorage.setItem("translocal", transactionDetails);
}
$(document)
		.ready(
				function() {
					// Add configuration for one or more providers.
					jso_configure({
						"PaymentServiceHub" : {
							client_id : "2131202023232312244122",
							redirect_uri : "http://localhost:8081/vendor/vendor.html",
							authorization : "http://localhost:8080/oauth/authorize",
						}
					});
					// Perform a data request
					$
							.oajax({
								url : "http://localhost:8080/psh/token",
								jso_provider : "PaymentServiceHub", // Will
																	// match the
																	// config
																	// identifier
								jso_scopes : [ "read" ], // List of scopes
															// (OPTIONAL)
								jso_allowia : true, // Allow user interaction
													// (OPTIONAL, default:
													// false)
								dataType : 'json',
								contentType : 'application/json',
								crossDomain : true,
								type : 'POST',
								data : JSON.stringify({
									"urn" : localStorage.getItem("urnlocal"),
									"transactionDetails" : localStorage.getItem("translocal")
								}),
								success : function(result) {
									console.log({
										response : result
									});
									$('#message').text(result.token);
								}
							});
					jso_wipe();
				});

function registerVendor() {
	$.ajax({
		url : "http://localhost:8082/PaymentServiceHub/psh/register",
		dataType : 'json',
		contentType : 'application/json',
		crossDomain : true,
		type : 'POST',
		data : JSON.stringify({
			"vendorName" : $('#name').val(),
			"redirectUri" : "http://localhost:8081/vendor/vendor.html",
			"domain" : "E-Commerce"
		}),
		success : function(result) {
			console.log({
				response : result
			});
			$('#message').text(result.token);
		}
	});
}