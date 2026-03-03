/**
 * Permission database with descriptions and risk assessments
 */
// Permission database - maps permission names to their metadata
// Using a Map to avoid duplicate key issues
const permissionMap = new Map();
function addPermission(perm) {
    permissionMap.set(perm.name.toLowerCase(), perm);
}
// Host permissions - highest risk
addPermission({
    name: '<all_urls>',
    description: 'Access to all websites. Can read and modify content on any webpage.',
    riskLevel: 'critical',
    category: 'host'
});
addPermission({
    name: '*://*/*',
    description: 'Access to all websites. Can read and modify content on any webpage.',
    riskLevel: 'critical',
    category: 'host'
});
addPermission({
    name: 'http://*/*',
    description: 'Access to all HTTP websites. Can read and modify content on any insecure webpage.',
    riskLevel: 'critical',
    category: 'host'
});
addPermission({
    name: 'https://*/*',
    description: 'Access to all HTTPS websites. Can read and modify content on any secure webpage.',
    riskLevel: 'critical',
    category: 'host'
});
// High-risk API permissions
addPermission({
    name: 'cookies',
    description: 'Read and modify cookies. Can access session data and potentially hijack accounts.',
    riskLevel: 'high',
    category: 'api'
});
addPermission({
    name: 'webRequest',
    description: 'Observe and analyze all network traffic. Can intercept, block, or modify requests.',
    riskLevel: 'high',
    category: 'api'
});
addPermission({
    name: 'webRequestBlocking',
    description: 'Block or modify network requests. Can intercept and alter web traffic.',
    riskLevel: 'critical',
    category: 'api'
});
addPermission({
    name: 'webRequestAuthProvider',
    description: 'Intercept authentication requests. Can steal credentials.',
    riskLevel: 'critical',
    category: 'api'
});
addPermission({
    name: 'webRequestFilterResponseData',
    description: 'Filter response data. Can intercept and modify HTTP responses.',
    riskLevel: 'high',
    category: 'api'
});
addPermission({
    name: 'debugger',
    description: 'Full debugging access to pages. Can intercept and modify all browser activity.',
    riskLevel: 'critical',
    category: 'debugging'
});
addPermission({
    name: 'proxy',
    description: 'Manage proxy settings. Can route all browser traffic through a remote server.',
    riskLevel: 'critical',
    category: 'network'
});
addPermission({
    name: 'vpnProvider',
    description: 'Create VPN configurations. Can route network traffic through the extension.',
    riskLevel: 'critical',
    category: 'network'
});
// Clipboard permissions
addPermission({
    name: 'clipboardRead',
    description: 'Read clipboard contents. Can access copied passwords, credit cards, and sensitive data.',
    riskLevel: 'high',
    category: 'clipboard'
});
addPermission({
    name: 'clipboardWrite',
    description: 'Modify clipboard contents. Can overwrite copied data.',
    riskLevel: 'medium',
    category: 'clipboard'
});
// Storage permissions
addPermission({
    name: 'storage',
    description: 'Store data locally. Used for extension settings and data persistence.',
    riskLevel: 'low',
    category: 'storage'
});
addPermission({
    name: 'unlimitedStorage',
    description: 'Store unlimited data locally. Could consume significant disk space.',
    riskLevel: 'low',
    category: 'storage'
});
// Tab permissions
addPermission({
    name: 'tabs',
    description: 'Access browser tabs and navigation. Can read sensitive URL and title information.',
    riskLevel: 'high',
    category: 'tab'
});
addPermission({
    name: 'activeTab',
    description: 'Access the active tab when user invokes the extension. Safer than "tabs" permission.',
    riskLevel: 'low',
    category: 'tab'
});
addPermission({
    name: 'tabCapture',
    description: 'Capture tab content as a stream. Can record browser activity.',
    riskLevel: 'high',
    category: 'tab'
});
addPermission({
    name: 'tabGroups',
    description: 'Create and manage tab groups. Can organize browser tabs.',
    riskLevel: 'low',
    category: 'tab'
});
// Network permissions
addPermission({
    name: 'declarativeNetRequest',
    description: 'Block or modify network requests declaratively. Used by ad blockers.',
    riskLevel: 'medium',
    category: 'network'
});
addPermission({
    name: 'declarativeNetRequestWithHostAccess',
    description: 'Modify network requests to host permissions. Used by ad blockers.',
    riskLevel: 'medium',
    category: 'network'
});
// Bookmark permissions
addPermission({
    name: 'bookmarks',
    description: 'Read and modify browser bookmarks. Can access user saved sites.',
    riskLevel: 'medium',
    category: 'bookmark'
});
// Download permissions
addPermission({
    name: 'downloads',
    description: 'Manage downloads. Can initiate file downloads and access download history.',
    riskLevel: 'medium',
    category: 'download'
});
addPermission({
    name: 'downloads.open',
    description: 'Open downloaded files. Can execute downloaded files.',
    riskLevel: 'critical',
    category: 'download'
});
// Geolocation
addPermission({
    name: 'geolocation',
    description: 'Access user location. Can track physical location.',
    riskLevel: 'high',
    category: 'geolocation'
});
// Notifications
addPermission({
    name: 'notifications',
    description: 'Display desktop notifications. Can show messages to users.',
    riskLevel: 'low',
    category: 'notification'
});
addPermission({
    name: 'notificationListener',
    description: 'Read desktop notifications. Can access notification content.',
    riskLevel: 'medium',
    category: 'notification'
});
// Privacy
addPermission({
    name: 'privacy',
    description: 'Manage privacy settings. Can modify browser privacy configurations.',
    riskLevel: 'high',
    category: 'privacy'
});
addPermission({
    name: 'browsingData',
    description: 'Clear browsing data. Can delete history, cookies, cache, etc.',
    riskLevel: 'high',
    category: 'privacy'
});
// Management
addPermission({
    name: 'management',
    description: 'Manage other extensions and apps. Can disable or uninstall extensions.',
    riskLevel: 'high',
    category: 'management'
});
// Various API permissions - low risk
addPermission({
    name: 'runtime',
    description: 'Access runtime information. Required for most extensions.',
    riskLevel: 'low',
    category: 'api'
});
addPermission({
    name: 'alarms',
    description: 'Schedule tasks. Used for background processing.',
    riskLevel: 'low',
    category: 'api'
});
addPermission({
    name: 'contextMenus',
    description: 'Add context menu items. Can add custom right-click options.',
    riskLevel: 'low',
    category: 'api'
});
addPermission({
    name: 'idle',
    description: 'Detect user idle state. Can monitor user activity.',
    riskLevel: 'low',
    category: 'api'
});
addPermission({
    name: 'webNavigation',
    description: 'Monitor navigation events. Can track browsing history.',
    riskLevel: 'medium',
    category: 'api'
});
addPermission({
    name: 'history',
    description: 'Access and modify browsing history. Can read sensitive browsing data.',
    riskLevel: 'high',
    category: 'api'
});
addPermission({
    name: 'topSites',
    description: 'Access most visited sites. Can expose user browsing habits.',
    riskLevel: 'medium',
    category: 'api'
});
addPermission({
    name: 'sessions',
    description: 'Access recently closed tabs/windows. Can reconstruct browsing sessions.',
    riskLevel: 'medium',
    category: 'api'
});
addPermission({
    name: 'search',
    description: 'Interact with search engines. Can perform searches.',
    riskLevel: 'low',
    category: 'api'
});
addPermission({
    name: 'scripting',
    description: 'Execute scripts in pages. Can modify webpage content.',
    riskLevel: 'high',
    category: 'api'
});
addPermission({
    name: 'nativeMessaging',
    description: 'Communicate with native applications. Can interact with system programs.',
    riskLevel: 'critical',
    category: 'api'
});
addPermission({
    name: 'power',
    description: 'Manage power settings. Can prevent system sleep.',
    riskLevel: 'low',
    category: 'api'
});
addPermission({
    name: 'system.cpu',
    description: 'Read CPU information. Can monitor system performance.',
    riskLevel: 'low',
    category: 'api'
});
addPermission({
    name: 'system.memory',
    description: 'Read memory information. Can monitor system performance.',
    riskLevel: 'low',
    category: 'api'
});
addPermission({
    name: 'system.storage',
    description: 'Read storage device info. Can monitor attached drives.',
    riskLevel: 'low',
    category: 'api'
});
addPermission({
    name: 'system.display',
    description: 'Read display information. Can monitor connected monitors.',
    riskLevel: 'low',
    category: 'api'
});
addPermission({
    name: 'fontSettings',
    description: 'Manage font settings. Can read font preferences.',
    riskLevel: 'low',
    category: 'api'
});
addPermission({
    name: 'gcm',
    description: 'Use Google Cloud Messaging. Required for push notifications.',
    riskLevel: 'low',
    category: 'api'
});
addPermission({
    name: 'identity',
    description: 'Access OAuth identity. Can authenticate users.',
    riskLevel: 'medium',
    category: 'api'
});
addPermission({
    name: 'identity.email',
    description: 'Access user email. Can read account email address.',
    riskLevel: 'medium',
    category: 'api'
});
addPermission({
    name: 'languageSettings',
    description: 'Manage language settings. Can modify browser languages.',
    riskLevel: 'low',
    category: 'api'
});
addPermission({
    name: 'loginState',
    description: 'Read login state. Can detect if user is logged in.',
    riskLevel: 'low',
    category: 'api'
});
addPermission({
    name: 'offscreen',
    description: 'Create offscreen documents. Can run background processing.',
    riskLevel: 'low',
    category: 'api'
});
addPermission({
    name: 'sidePanel',
    description: 'Use side panel. Can display extension UI in side panel.',
    riskLevel: 'low',
    category: 'api'
});
addPermission({
    name: 'tts',
    description: 'Access text-to-speech engine. Could be used to speak sensitive information.',
    riskLevel: 'medium',
    category: 'api'
});
addPermission({
    name: 'ttsEngine',
    description: 'Implement a text-to-speech engine. Can intercept voice data.',
    riskLevel: 'medium',
    category: 'api'
});
// Experimental
addPermission({
    name: 'experimental',
    description: 'Access experimental APIs. May have unstable behavior.',
    riskLevel: 'medium',
    category: 'experimental'
});
// Export as regular object for backward compatibility
export const permissionDatabase = Object.fromEntries(permissionMap);
/**
 * Dangerous permission combinations that should be flagged
 */
export const dangerousCombinations = [
    {
        permissions: ['<all_urls>', 'webRequest'],
        description: 'All URLs + webRequest allows intercepting all web traffic',
        severity: 'critical'
    },
    {
        permissions: ['<all_urls>', 'webRequestBlocking'],
        description: 'All URLs + webRequestBlocking allows blocking/modifying all web traffic',
        severity: 'critical'
    },
    {
        permissions: ['<all_urls>', 'cookies'],
        description: 'All URLs + cookies allows stealing session cookies',
        severity: 'critical'
    },
    {
        permissions: ['<all_urls>', 'webRequest', 'cookies'],
        description: 'All URLs + webRequest + cookies enables full traffic interception',
        severity: 'critical'
    },
    {
        permissions: ['http://*/*', 'webRequest'],
        description: 'HTTP access + webRequest allows intercepting insecure traffic',
        severity: 'critical'
    },
    {
        permissions: ['http://*/*', 'cookies'],
        description: 'HTTP access + cookies allows stealing session cookies from HTTP sites',
        severity: 'critical'
    },
    {
        permissions: ['tabs', 'scripting'],
        description: 'Tabs + scripting allows modifying any page content',
        severity: 'high'
    },
    {
        permissions: ['<all_urls>', 'scripting'],
        description: 'All URLs + scripting allows executing scripts on any website',
        severity: 'critical'
    },
    {
        permissions: ['proxy', 'storage'],
        description: 'Proxy + storage could store proxy configuration for MitM attacks',
        severity: 'critical'
    },
    {
        permissions: ['debugger', 'http://*/*'],
        description: 'Debugger + HTTP access allows intercepting HTTP traffic',
        severity: 'critical'
    },
    {
        permissions: ['clipboardRead', 'tabs'],
        description: 'Clipboard read + tabs can steal sensitive copied data from any tab',
        severity: 'high'
    },
    {
        permissions: ['history', 'tabs'],
        description: 'History + tabs can correlate browsing history with current activity',
        severity: 'high'
    },
    {
        permissions: ['bookmarks', 'http://*/*'],
        description: 'Bookmarks + HTTP access could exfiltrate bookmark data',
        severity: 'high'
    },
    {
        permissions: ['downloads', 'http://*/*'],
        description: 'Downloads + HTTP access could download malicious content',
        severity: 'high'
    },
    {
        permissions: ['nativeMessaging', '<all_urls>'],
        description: 'Native messaging + all URLs can communicate with any server',
        severity: 'critical'
    },
    {
        permissions: ['privacy', 'browsingData'],
        description: 'Privacy + browsing data can clear user data',
        severity: 'high'
    },
    {
        permissions: ['management', 'http://*/*'],
        description: 'Management + HTTP could install malicious extensions',
        severity: 'critical'
    },
    {
        permissions: ['geolocation', '<all_urls>'],
        description: 'Geolocation + all URLs can track user location on any site',
        severity: 'high'
    },
    {
        permissions: ['tabCapture', '<all_urls>'],
        description: 'Tab capture + all URLs can record activity on any site',
        severity: 'critical'
    },
    {
        permissions: ['webRequestAuthProvider', '<all_urls>'],
        description: 'Auth provider + all URLs can intercept authentication',
        severity: 'critical'
    }
];
/**
 * Risk score weights for calculations
 */
export const riskWeights = {
    critical: 10,
    high: 5,
    medium: 2,
    low: 1
};
/**
 * Get a permission from the database
 */
export function getPermission(name) {
    return permissionMap.get(name.toLowerCase());
}
/**
 * Check if a permission exists in the database
 */
export function hasPermission(name) {
    return permissionMap.has(name.toLowerCase());
}
