var OAuth = require('OAuthClass'),
	Sha   = require('ShaClass');

function OAuthAdapter( pConsumerSecret, pConsumerKey, pSignatureMethod ){
	this.consumerSecret = pConsumerSecret;
	this.consumerKey = pConsumerKey;
	this.signatureMethod = pSignatureMethod;
	
	this.accessor = {
		consumerSecret: pConsumerSecret,
		tokenSecret: ''
	};
	this.actionsQueue = [];
	this.currentWindow = null;
	this.newWindow = null;
	this.webView = null;
	
	this.signupCallback = null;
	this.oauthCallbackHandler = new OAuthCallbackHandler();
}

OAuthAdapter.prototype.loadAccessToken = function( pService ){
	Ti.API.debug('Loading access token for service [' + pService + '].' + Ti.Filesystem.applicationDataDirectory );
	
	var file = Ti.Filesystem.getFile( Ti.Filesystem.applicationDataDirectory + 'config', pService + '.config');
	if (file.exists() == false) return false;
	
	var contents = file.read();
	if (contents == null) return false;
	try { var config = JSON.parse(contents.text); } catch(ex){ return false; }
	
	if ( config.accessToken && config.accessTokenSecret) {
		this.oauthCallbackHandler.setAccessToken( config.accessToken );
		this.oauthCallbackHandler.setAccessTokenSecret( config.accessTokenSecret );
		return true;
	}
	Ti.API.debug('Loading access token: done [this.accessToken:' + this.accessToken + '][this.accessTokenSecret:' + this.accessTokenSecret + '].');
	return true;
};

OAuthAdapter.prototype.unloadAccessToken = function(){
	this.oauthCallbackHandler.setAccessToken( null );
	this.oauthCallbackHandler.setAccessTokenSecret( null );
}

OAuthAdapter.prototype.setAccessToken = function(id, pService){
	Ti.API.debug("setAccesstoken " + id + " " + pService);
	
	switch( pService ){
		case 'twitter':
			var idFile = Ti.Filesystem.getFile(Ti.Filesystem.applicationDataDirectory + 'config',id +'.'+pService + '.config');
			if (idFile.exists() == false) return;
			
			var contents = idFile.read();
			if (contents == null) return;
			
			try{
				var config = JSON.parse(contents.text);
				if (config.accessToken) this.oauthCallbackHandler.setAccessToken( config.accessToken );
				if (config.accessTokenSecret) this.oauthCallbackHandler.setAccessTokenSecret( config.accessTokenSecret );
				
			} catch(ex) {
				Ti.API.debug(ex);
				return;
			}
			break;
	}
	return true;
}

OAuthAdapter.prototype.deleteAccessToken = function(pService){
	var file = Ti.Filesystem.getFile(Ti.Filesystem.applicationDataDirectory + 'config', pService + '.config');
	if ( file.exists() ) {
		this.oauthCallbackHandler.setAccessToken( null )
		this.oauthCallbackHandler.setAccessTokenSecret( null )
		file.deleteFile();
	}
}

OAuthAdapter.prototype.saveAccessToken = function(pService){
	Ti.API.debug('Saving access token [' + pService + '].');
	var file = Ti.Filesystem.getFile(Ti.Filesystem.applicationDataDirectory + 'config', pService + '.config');
	if (file == null) file = Ti.Filesystem.createFile(Ti.Filesystem.applicationDataDirectory + 'config', pService + '.config');
	file.write(JSON.stringify({
		accessToken: this.oauthCallbackHandler.getAccessToken(),
		accessTokenSecret: this.oauthCallbackHandler.getAccessTokenSecret()
	}));
	Ti.API.debug('Saving access token: done.');
};

OAuthAdapter.prototype.isAuthorized = function(){
	return ! (this.oauthCallbackHandler.getAccessToken() == null || this.oauthCallbackHandler.getAccessTokenSecret() == null);
};

OAuthAdapter.prototype.getRequestToken = function(pUrl, callback, responseHandler){
	this.accessor.tokenSecret = '';
	
	var message = createMessage(pUrl, this.consumerKey, this.signatureMethod);
	OAuth.setTimestampAndNonce(message);
	OAuth.completeRequest(message, this.accessor, callback);
	
	var parameterMap = OAuth.getParameterMap(message.parameters);
	for (var p in parameterMap) Ti.API.debug('param : ' + p + ': ' + parameterMap[p]);
	
	var oauthCallbackHandler = this.oauthCallbackHandler;
	var client = Ti.Network.createHTTPClient();
	client.open('POST', pUrl);
	client.onload = function() {
		var responseParams = OAuth.getParameterMap(client.responseText);
		oauthCallbackHandler.setRequestToken(responseParams.oauth_token);
		oauthCallbackHandler.setRequestTokenSecret(responseParams.oauth_token_secret);
		Ti.API.debug('request token got the following response: ' + client.responseText);
		responseHandler.call(this, client.responseText);
	};
	client.onerror = function(e) {
		for( var i in e )
		Ti.API.error("getRequestToken failed: " + i + ' : ' + e[i]);
	}
	client.send(parameterMap);
}
	
OAuthAdapter.prototype.getAccessToken = function(pUrl, callback){
	this.accessor.tokenSecret = this.oauthCallbackHandler.getRequestTokenSecret();
	var message = createMessage(pUrl, this.consumerKey, this.signatureMethod);
	message.parameters.push(['oauth_token', this.oauthCallbackHandler.getRequestToken()]);
	message.parameters.push(['oauth_verifier', this.oauthCallbackHandler.getPin()]);
	
	OAuth.setTimestampAndNonce(message);
	OAuth.completeRequest(message, this.accessor);
	
	var parameterMap = OAuth.getParameterMap(message.parameters);
	for (var p in parameterMap) Ti.API.debug('Param : ' + p + ': ' + parameterMap[p]);
	
	var oauthCallbackHandler = this.oauthCallbackHandler;
	var client = Ti.Network.createHTTPClient();
	client.open('POST', pUrl, true);
	client.onload = function() {
		var responseParams = OAuth.getParameterMap(client.responseText);
		oauthCallbackHandler.setAccessToken(responseParams.oauth_token);
		oauthCallbackHandler.setAccessTokenSecret(responseParams.oauth_token_secret);
		Ti.API.debug('*** get access token, Response: ' + client.responseText);
		callback.call(this, client.responseText);
	}
	client.onerror = function(e) {
		Ti.API.error("getAccessToken failed: " + e);
		for (var p in e) Ti.API.error(p + ': ' + e[p]);
	}
	client.send(parameterMap);
};

OAuthAdapter.prototype.showTwitterUI = function(window, pUrl, pPinCallbackType){
	this.currentWindow = window;
	this.newWindow = Ti.UI.createWindow({barColor:'#333', title:L('Twitter_Login')});
	this.webView = Ti.UI.createWebView({ url: pUrl });
	this.newWindow.add(this.webView);
	this.currentWindow.tab.open(this.newWindow);
	
	var newWindow = this.newWindow;
	var oauthCallbackHandler = this.oauthCallbackHandler;
	var webView = this.webView;
	this.webView.addEventListener('load', function(e){
		oauthCallbackHandler.twitterUICallback(e, newWindow, webView, pPinCallbackType);
	} );
};

OAuthAdapter.prototype.generateParams = function(pUrl, pParameters){
	Ti.API.debug('Sending a message to the service at [' + pUrl + '] with the following params: ' + JSON.stringify(pParameters));
	if(
		this.oauthCallbackHandler.getAccessToken() == null ||
		this.oauthCallbackHandler.getAccessTokenSecret() == null
	){
		this.actionsQueue.push({
			url: pUrl,
			parameters: pParameters
		});
		return;
	}
	this.accessor.tokenSecret = this.oauthCallbackHandler.getAccessTokenSecret();
	var message = createMessage(pUrl, this.consumerKey, this.signatureMethod);
	message.parameters.push(['oauth_token', this.accessToken]);
	
	for (p in pParameters) message.parameters.push(pParameters[p]);
	OAuth.setTimestampAndNonce(message);
	OAuth.completeRequest(message, this.accessor);
	
	return OAuth.getParameterMap(message.parameters);
};

OAuthAdapter.prototype.createOAuthHeader = function (params) {
	var pUrl            = params.url;
	var pMethod         = params.method || "POST";
	var message = createMessage(pUrl, this.consumerKey, this.signatureMethod, pMethod);
	
	this.accessor.tokenSecret = this.oauthCallbackHandler.getAccessTokenSecret();
	message.parameters.push(['oauth_token', this.oauthCallbackHandler.getAccessToken()]);
	
	OAuth.setTimestampAndNonce(message);
	OAuth.SignatureMethod.sign(message, this.accessor);
	
	var parameterMap = OAuth.getParameterMap(message.parameters);
	var oAuthHeaderElms = [];
	for (var p in parameterMap) {
		oAuthHeaderElms.push( encodeURIComponent(p) + "=" + encodeURIComponent(parameterMap[p]) );
	}
	return 'OAuth ' + oAuthHeaderElms.sort().join(', ');
};

OAuthAdapter.prototype.execute = function( url, params, callback, method ){
	var method = method ? method : 'POST';
	if (method == 'GET') url = makeGetURL(url, parameterMap);
	
	if(
		this.oauthCallbackHandler.getAccessToken() == null ||
		this.oauthCallbackHandler.getAccessTokenSecret() == null
	){
		this.actionsQueue.push({
			url: url,
			parameters: params
		});
		Ti.API.debug("invalid param");
		callback(null, { status: 401 });
		
	} else {
		this.accessor.tokenSecret = this.oauthCallbackHandler.getAccessTokenSecret();
		var message = createMessage(url, this.consumerKey, this.signatureMethod, method);
		message.parameters.push(['oauth_token', this.oauthCallbackHandler.getAccessToken()]);
		for (p in params){ message.parameters.push(params[p]); }
		
		OAuth.setTimestampAndNonce(message);
		OAuth.completeRequest(message, this.accessor);
		var parameterMap = OAuth.getParameterMap(message.parameters);
		for (var p in parameterMap) Ti.API.debug(p + ': ' + parameterMap[p]);
		
		var client = Ti.Network.createHTTPClient();
		client.onload = function(){
			client.onload = null;
			client.onreadystatechange = null;
			client.ondatastream = null;
			client.onerror = null;
			client = null;
			
			if( this.status == 200 ) {
				Ti.API.debug('data from http...' + this.responseText);
				
				try{ var request = JSON.parse(this.responseText); }
				catch( e ){ callback(null, {status:401}); }
				
				if ( request ) { callback(request, {status: 200}); }
				else { callback(null, {status: 400}); }
				
			} else {
				callback(null, {status: this.status });
			}
		};
		
		client.onerror = function(){
			client.onload = null;
			client.onreadystatechange = null;
			client.ondatastream = null;
			client.onerror = null;
			client = null;
			
			Ti.API.debug("onload error " + url + ' : ' + this.responseText);
			if( this.status ) { callback(null, {status: this.status} ) }
			else { callback(null, {status: this.status}); }
		};
		client.setTimeout(10000);
		
		if( method == 'GET' ){
			var finalUrl = OAuth.addToURL(url, parameterMap);
			client.open(method, finalUrl, false);
			client.send();
		} else {
			client.open(method, url, false);
			client.send(parameterMap);
		}
		Ti.API.debug("onload now " + url);
	}
};


function OAuthCallbackHandler(){
	this.pin = null;
	this.requestToken = null;
	this.requestTokenSecret = null;
	this.accessToken = null;
	this.accessTokenSecret = null;
}

OAuthCallbackHandler.prototype.getPin = function(){
	return this.pin;
}

OAuthCallbackHandler.prototype.setAccessToken = function(token){
	this.accessToken = token;
}
OAuthCallbackHandler.prototype.setAccessTokenSecret = function(secret){
	this.accessTokenSecret = secret;
}
OAuthCallbackHandler.prototype.getAccessToken = function(){
	return this.accessToken;
}
OAuthCallbackHandler.prototype.getAccessTokenSecret = function(){
	return this.accessTokenSecret;
}

OAuthCallbackHandler.prototype.setRequestToken = function(token){
	this.requestToken = token;
}
OAuthCallbackHandler.prototype.setRequestTokenSecret = function(secret){
	this.requestTokenSecret = secret;
}
OAuthCallbackHandler.prototype.getRequestToken = function(){
	return this.requestToken;
}
OAuthCallbackHandler.prototype.getRequestTokenSecret = function(){
	return this.requestTokenSecret;
}

OAuthCallbackHandler.prototype.twitterUICallback = function(e, newWindow, webView, callbackType){
	var h = e.source.html ? e.source.html : e.source.evalJS("document.documentElement.innerHTML");
	var startPin = h.indexOf('<code>', 0);
	
	if(startPin != -1) {
		startPin = startPin + 6;
		var stopPin = h.indexOf('</code>', startPin);
		this.pin = h.substr(startPin, (stopPin - startPin));
		
		if( this.pin.length == 7 && callbackType )
		setTimeout(function() { Ti.App.fireEvent("ReceivePinCallback", { callbackType: callbackType } ) }, 100);
		
		if ( newWindow ) {
			try{ newWindow.close(); }
			catch(ex) { Ti.API.debug('Cannot destroy the authorize UI. Ignoring.'); }
		}
	}
};

var createMessage = function(pUrl, key, signature, method){
	var method = method ? method : 'POST';
	var message = {
		action: pUrl,
		method: method,
		parameters: []
	};
	message.parameters.push(['oauth_consumer_key', key]);
	message.parameters.push(['oauth_signature_method', signature]);
	return message;
};

var makeGetURL = function(url, parameterMap) {
	var query = [];
	var keys = [];
	for (var p in parameterMap) {
	if(parameterMap.hasOwnProperty(p)){
		query.push( encodeURIComponent(p) + "=" + encodeURIComponent(parameterMap[p]) ); 
	}
	}
	query.sort();
	if (query.length) {
		query = query.join('&');
		return url + ((url.indexOf('?') >= 0) ? '&' : '?') + query;
	}
	return url;
};

module.exports = OAuthAdapter;

