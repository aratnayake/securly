function FindProxyForURL(url, host) {
    // NWEA Testing Domains - Direct access for secure testing
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

    // Example: Use proxy for your domain
    if (shExpMatch(host, "*.yourdomain.com")) {
        return "PROXY proxy.yourdomain.com:8080";
    }

    // Default: direct connection
    return "DIRECT";
}