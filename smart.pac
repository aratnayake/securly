// FID: "securly@ais.at"
// USER: ""
// Variables provided by PHP
var cluster = "uk";    // Used to determine what DNS servers to accessa
var api_endpoint = "uk.v1api.securly.com";
var fid = "securly@ais.at";			  // Reserved for future use	
var unifyid = false;
var stateid = "1psrmkrr6adw0";	  // This users state data
var did = "75p80jt46wdv";			  // Used to track the device
var logging = true; // Extra logging

// Informational
var user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
var ua_browser = "Chrome 140.0.0";
var ua_os = "Windows 10";
var pac_mode = "filter";  // "filter" or "bypass" - Filtering browsers bypassing for everything else

// Variables calculated by the pac
// @todo This needs to be securly.com for production
var proxy_server = "PROXY uk-dp.securly.com:80; DIRECT";
var blackhole = "PROXY 240.0.0.1:80";

var internal_ip = 0;
// The cache buster is incremented whenever smartpac detects a circumstance that would
// require cache invalidation.
var cb = 0;
var brokered = false;
var last_sync_timestamp = 0;
var now = 0;
var securlydns = false;
var pause = false;
var kill_switch_exemption = false;
function FindProxyForURL(url, host) {
    // Example: Use proxy for your domain
    if (shExpMatch(host, "*.yourdomain.com")) {
        return "PROXY proxy.yourdomain.com:8080";
    }

    // Default: direct connection
    return "DIRECT";


	now = new Date();
	now = Math.floor(now.getTime() / 1000);

	if (host[host.length-1] == ".") {
		// Remove Trailing Dot
		host = host.slice(0, -1);
	}

	// If FID is exemption for killswitch, below logic will be bypassed
	if(kill_switch_exemption == false) {
		// SmartPac local kill switch
		var killswitch = dnsResolve("smartpac-shutdown.securly.com");
		if (killswitch != "127.0.0.2" && killswitch != "204.110.220.2") {
			Debug("SmartPac Killswitch active");
			return "DIRECT";
		}
	}
	
	// Is this website interesting from a filter point of view for this customer?  Then proxy.
	if ( url[4] == "s" ) {
		protocol = "s";
	} else {
		protocol = "h";
	}
	var dns = dnsResolve("securlydns.securly.com");
	if (dns == "127.0.0.1" || dns == "204.110.220.1") {
		securlydns = true;
	} else {
		securlydns = false;
	}

	if (isInNet(host, "127.0.0.0", "255.0.0.0")) {
		return "DIRECT";
	}

	// Check for API calls
	CheckApi(url, host);

	// Invalidate policy cache when our internal IP address changes
	if (myIpAddress() != internal_ip) {
		Debug("IP O:"+internal_ip+" N:"+myIpAddress()+" IP Address change");
		internal_ip = myIpAddress();
		cb++;
		last_sync_timestamp = 0;
	}

	var id = transmitStateInformation(true);

	// Do not use proxy to comminate with WWW (By convention)
	if (dnsDomainIs(host, ".securly.com")) {
		return "DIRECT";
	}

	//REL-5455 always send firestore direct
	if (host == "firestore.googleapis.com") {
		return "DIRECT";
	}

	//REL-7315 Websocket connection bypass
	if (url.substring(0, 6) === "wss://") {
        	return "DIRECT";
	}

	if (host.endsWith(".local")) {
		return "DIRECT";
	}

	// Do not proxy traffic to private IP addresses
	if (
		isInNet(host, "192.168.0.0", "255.255.0.0") ||
		isInNet(host, "10.0.0.0", "255.0.0.0") ||
		isInNet(host, "172.16.0.0", "255.240.0.0")
		) {
		return "DIRECT";
	}

	// === NWEA TESTING DOMAINS - Direct access for secure testing ===
	if (
		dnsDomainIs(host, ".mapnwea.org") ||
		dnsDomainIs(host, ".nwea.org") ||
		host == "fonts.googleapis.com" ||
		host == "gstatic.com" ||
		host == "sso.mapnwea.org" ||
		host == "teach.mapnwea.org" ||
		host == "start.mapnwea.org" ||
		host == "auth.nwea.org" ||
		dnsDomainIs(host, ".browser-intake-datadoghq.com") ||
		dnsDomainIs(host, ".datadoghq-browser-agent.com") ||
		host == "newrelic.com" ||
		host == "cdn.mapnwea.org" ||
		host == "cdn.jsdelivr.net" ||
		host == "item-presenter-lib.mapnwea.org" ||
		host == "test.mapnwea.org" ||
		host == "practice.mapnwea.org" ||
		host == "studentresources.nwea.org" ||
		dnsDomainIs(host, ".launchdarkly.com")
	) {
		// Debug("NWEA domain bypass: " + host);
		return "DIRECT";
	}
	// === END NWEA EXCEPTIONS ===

	if (pause == true) {
		return handlePause(host);
	}

	// @todo unblock IP addresses
	// @todo write and implement a normalization function

	var flags = 0;

	if ( url[4] == "s" ) {
		flags |= (1 << 0);
	} 

	if (securlydns) {
		flags |= (1 << 1);
	}

	// Is this website interesting from a filter point of view for this customer?  Then proxy.
	var action = dnsResolve(host+"."+flags+"."+id+"."+cb+".prx."+api_endpoint);
	if ( action == "204.110.220.2") {			// Must Broker
		transmitStateInformation(false);
		return proxy_server;
	} else if ( action == "204.110.220.4") {	// May Broker
		if (now - last_sync_timestamp > 10*60) {
			Debug("Taking optional brokering opportunity");
			transmitStateInformation(false);
			// Updating last_sync_timestamp must be done after transmitStateInformation to avoid creating a race condition. The dnsResolve function blocks
			// the first call of FindProxyForURL so the JS engine lets the second one run for optimization. However, when this happens and we get to this 
			// if statement, last_sync_timestamp is already updated and so the second call goes to the else and returns DIRECT before the first call can
			// finish resolving.
			last_sync_timestamp = now;
			return proxy_server;
		} else {
			Debug("Skipping optional brokering opportunity ("+(now-last_sync_timestamp)+","+now+","+last_sync_timestamp+")");
			return "DIRECT";
		}
	} else if ( action == "204.110.220.3" ) {	// Blackhole
		return blackhole;
	} else if ( action == "204.110.220.5" ) {	// engage pause
		transmitStateInformation(false);
		pause = true;
		cb++;
		return handlePause(host);
	} else {								// Do not broker
		return "DIRECT";
	}
}

// When we're paused, this function is called to see if we're still paused
function handlePause(host) {
	var action = dnsResolve(host+"."+did+"."+cb+".pse."+api_endpoint);
	if (action == "204.110.220.1") {
		// Pause this site with squid
		return proxy_server;
	} else if (action == "204.110.220.2") {
		// Pause this site with the blackhole
		return blackhole;
	} else if (action == "204.110.220.3") {
		// Pause is over, go back online
		pause = false;
		cb++;
		return "DIRECT";
	} else {
		// Let this site go
		return "DIRECT";
	}
}


// This makes sure the remote server always knows who we are, even if our remote state has expired
// mode indicates if this call should activate when brokered is true or false
// Mode == true is when we're operating in a normalish routinely brokered mode
// Mode == false only transmits state the first time it happens
// brokered gets set to true the first time we broker, and remains true
// If we have brokered, we use the did for our id.  If we have not brokered, we use the stateid for our id
// This function returns the id we should use
function transmitStateInformation(mode) {
	if (unifyid == true) {
		dnsResolveWrapper(internal_ip+"."+did+"."+cb+".mip."+api_endpoint);
		return did;
	}

	if (brokered == mode) {
		dnsResolveWrapper(stateid+"."+did+".state."+api_endpoint);
		dnsResolveWrapper(internal_ip+"."+did+"."+cb+".mip."+api_endpoint);
		brokered = true;
	}

	if (brokered == true) {
		return did;
	} else {
		return stateid;
	}
}

// This is a wrapper for dns resolve because IE PACs seem to break when you call dnsResolve
// while ignoring the return value.  This seems to work around the bug.
function dnsResolveWrapper(dnsEndpoint) {
	return dnsResolve(dnsEndpoint);
}

function CheckApi(url, host) {
	var rpc_endpoint = "\\.pacrpc\\."+api_endpoint;
	var found;
	var re;
	var token;
	
	re = new RegExp("^([^.]*)sync"+rpc_endpoint, 'i');
	found = host.match(re);
	if (found !== null) {
		token = found[1];
		Debug("Restore Token API Endpoint - Token: "+token);
		cb++;
		last_sync_timestamp = now;
		var dnsapi = did+"."+token+".res."+api_endpoint;
		dnsResolveWrapper(dnsapi);
	}
}

function Debug(string) {
	var debug = "alert";

	if (debug == "alert") {
		alert("smart_pac: "+string);
	} else if (debug == "dns") {
		DebugDns(string);
	}
}

function DebugDns(string) {
	var id = makeid(5);
	var hex = AsciiToHex(string).substring(0,62);
	
	var dnsapi = hex+"."+did+"."+id+".debug."+api_endpoint;
	dnsResolveWrapper(dnsapi);
}

function makeid(size) {
	var text = "";
	var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

	for (var i = 0; i < size; i++) {
		text += possible.charAt(Math.floor(Math.random() * possible.length));
	}

	return text;
}

function AsciiToHex(str) {
        var arr1 = [];
        for (var n = 0, l = str.length; n < l; n ++) {
                var hex = Number(str.charCodeAt(n)).toString(16);
                arr1.push(hex);
        }
        return arr1.join('');
}
