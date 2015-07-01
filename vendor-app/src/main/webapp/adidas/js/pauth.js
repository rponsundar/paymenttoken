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
if (localStorage.getItem("transactionDetailsLocal") === ""
	|| !localStorage.getItem("transactionDetailsLocal")) {
var transactionDetails = getParameterByName('transactionDetails');
localStorage.setItem("transactionDetailsLocal", transactionDetails);
}

$(document)
		.ready(
				function() {
					// Add configuration for one or more providers.
					jso_configure({
						"PaymentServiceHub" : {
							client_id : configData.client_id,
							redirect_uri : configData.redirect_uri,
							authorization : configData.authorization
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
									"transactionDetails" : localStorage.getItem("transactionDetailsLocal")
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

