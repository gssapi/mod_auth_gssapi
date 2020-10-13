mod_auth_gssapi
===============

Intro
-----

This module has been built as a replacement for the aging mod_auth_kerb.
Its aim is to use only GSSAPI calls and be as much as possible agnostic
of the actual mechanism used.

Dependencies
------------

A modern version of MIT's Krb5 distribution or any GSSAPI implementation
that supports the [credential store
extension](http://k5wiki.kerberos.org/wiki/Projects/Credential_Store_extensions)
is necessary to achieve full functionality. Reduced functionality is
provided without these extensions.

    MIT krb5 (>=1.11)
    Apache httpd (>=2.4.11)

### Tests

To run tests, you also need:

* The Kerberos 5 Key-Distribution-Center (`krb5-kdc` package on Debian,
  `krb5-server` on Fedora)
* Packages `mod_session`, `krb5-workstation`, `python3-requests-gssapi`,
  and `python3-gssapi` on Fedora
* Some tests require `krb5-pkinit` package on fedora and krb5 >= 1.15.
* [nss_wrapper](https://cwrap.org/nss_wrapper.html), packaged in Fedora
* [socket_wrapper](https://cwrap.org/socket_wrapper.html), packaged in Fedora

Installation
------------

    autoreconf -fi
    ./configure
    make
    make install


Configuration
-------------

Apache authentication modules are usually configured per location, see the
[mod_authn_core](https://httpd.apache.org/docs/2.4/mod/mod_authn_core.html)
documentation for the common directives

### Basic configuration

The simplest configuration scheme specifies just one directive, which is the
location of the keytab.

#### Example
    <Location /private>
        AuthType GSSAPI
        AuthName "GSSAPI Single Sign On Login"
        GssapiCredStore keytab:/etc/httpd.keytab
        Require valid-user
    </Location>

Your Apache server need read access to the keytab configured.
If your Kerberos implementation does not support the credential store
extensions you can also simply set the KRB5_KTNAME environment variable in the
Apache init script and skip the GssapiCredStore option completely.


Environment Variables
---------------------

(Note: these are not process environment variables, but rather Apache
environment variables, as described
[in the apache docs](https://httpd.apache.org/docs/2.4/env.html).)

### gssapi-no-negotiate

This environment variable is used to suppress setting Negotiate headers.  Not
sending these headers is useful to work around browsers that do not handle
them properly (and incorrectly show authentication popups to users).

#### Example

For instance, to suppress negotiation on Windows browsers, one could set:

    BrowserMatch Windows gssapi-no-negotiate



Configuration Directives
------------------------

### Alphabetic List of Directives

[GssapiAcceptorName](#gssapiacceptorname)<br>
[GssapiAllowedMech](#gssapiallowedmech)<br>
[GssapiBasicAuth](#gssapibasicauth)<br>
[GssapiBasicAuthMech](#gssapibasicauthmech)<br>
[GssapiBasicTicketTimeout](#gssapibasicticketvalidity)<br>
[GssapiConnectionBound](#gssapiconnectionbound)<br>
[GssapiCredStore](#gssapicredstore)<br>
[GssapiDelegCcacheDir](#gssapidelegccachedir)<br>
[GssapiDelegCcacheEnvVar](#gssapidelegccacheenvvar)<br>
[GssapiDelegCcachePerms](#gssapidelegccacheperms)<br>
[GssapiDelegCcacheUnique](#gssapidelegccacheunique)<br>
[GssapiImpersonate](#gssapiimpersonate)<br>
[GssapiLocalName](#gssapilocalname)<br>
[GssapiNameAttributes](#gssapinameattributes)<br>
[GssapiNegotiateOnce](#gssapinegotiateonce)<br>
[GssapiPublishErrors](#gssapipublisherrors)<br>
[GssapiPublishMech](#gssapipublishmech)<br>
[GssapiRequiredNameAttributes](#gssapirequirednameattributes)<br>
[GssapiSessionKey](#gssapisessionkey)<br>
[GssapiSignalPersistentAuth](#gssapisignalpersistentauth)<br>
[GssapiSSLonly](#gssapisslonly)<br>
[GssapiUseS4U2Proxy](#gssapiuses4u2proxy)<br>
[GssapiUseSessions](#gssapiusesessions)<br>


### GssapiSSLonly

Forces the authentication attempt to fail if the connection is not being
established over TLS. The default is "Off", which could be helpful in a
local development environment, but we do not recommend for production
deployments. A passive adversary could listen to the plaintext HTTP connection
to observe any private information in the client's request or server's
response (for example: the full HTTP response body, or any web application
session cookies, etc). You should only use mod_auth_gssapi with HTTPS in
production, so we recommend that you *enable* this setting in production for
added protection.

- **Enable with:** GssapiSSLonly On
- **Default:** GssapiSSLonly Off


### GssapiLocalName

Tries to map the client principal to a local name using the gss_localname()
call. This requires configuration in the /etc/krb5.conf file in order to allow
proper mapping for principals not in the default realm (for example a user
coming from a trusted realm).
See the 'auth_to_local' option in the [realms] section of krb5.conf(5)

When `GssapiLocalName` is set to `on`, mod_auth_gssapi will set the
`REMOTE_USER` variable to the resolved user name. mod_auth_gssapi will also
set the `GSS_NAME` variable to the complete client principal name.

- **Enable with:** GssapiLocalName On
- **Default:** GssapiLocalName Off


### GssapiConnectionBound

This option is not needed for krb5 or basic auth in almost all cases.  It
incurs overhead, so leaving it off is recommended.

For NTLMSSP (and any other GSS mechanisms that require more than one
round-trip to complete authentication), it is necessary to bind to the
authentication to the connection in order to keep the state between
round-trips.  With this option, incomplete context are stored in the
connection and retrieved on the next request for continuation.

- **Enable with:** GssapiConnectionBound On
- **Default:** GssapiConnectionBound Off


### GssapiSignalPersistentAuth

For clients that make use of Persistent-Auth header, send the header according
to GssapiConnectionBound setting.

- **Enable with:** GssapiSignalPersistentAuth On
- **Default:** GssapiSignalPersistentAuth Off


### GssapiUseSessions

In order to avoid constant and costly re-authentication attempts for every
request, mod_auth_gssapi offers a cookie based session method to maintain
authentication across multiple requests. GSSAPI uses the mod_sessions module
to handle cookies so that module needs to be activated and configured.
GSSAPI uses a secured (encrypted + MAC-ed) payload to maintain state in the
session cookie. The session cookie lifetime depends on the lifetime of the
GSSAPI session established at authentication.
**NOTE**: It is important to correctly set the SessionCookieName option.
See the
[mod_sessions](http://httpd.apache.org/docs/current/mod/mod_session.html)
documentation for more information.

- **Enable with:** GssapiUseSessions On
- **Default:** GssapiUseSessions Off

#### Example
    GssapiUseSessions On
    Session On
    SessionCookieName gssapi_session path=/private;httponly;secure;


### GssapiSessionKey

When GssapiUseSessions is enabled a key use to encrypt and MAC the session
data will be automatically generated at startup, this means session data will
become unreadable if the server is restarted or multiple servers are used and
the client is load balanced from one to another. To obviate this problem the
admin can choose to install a permanent key in the configuration so that
session data remain accessible after a restart or by multiple servers
sharing the same key.

Two schemes to read persistent keys are provided, 'key' and 'file'.

- 'key'
    A key is read from the configuration directive.
    The key must be a base64 encoded raw key of 32 bytes of length.

- 'file'
    A file on the file system is used to store the key. If the file does not
    exists one is created with a randomly generated key during the first
    execution.


#### Examples
    GssapiSessionKey key:VGhpcyBpcyBhIDMyIGJ5dGUgbG9uZyBzZWNyZXQhISE=
    GssapiSessionKey file:/var/lib/httpd/secrets/session.key


### GssapiCredStore

The GssapiCredStore option allows to specify multiple credential related
options like keytab location, client_keytab location, ccache location etc.

#### Example
    GssapiCredStore keytab:/etc/httpd.keytab
    GssapiCredStore ccache:FILE:/var/run/httpd/krb5ccache


### GssapiDelegCcacheDir

If delegation of credentials is desired credentials can be exported in a
private directory accessible by the Apache process.
The delegated credentials will be stored in a file named after the client
principal and a request environment variable (`KRB5CCNAME` by default) will be
set to point to that file.

#### Example
    GssapiDelegCcacheDir /var/run/httpd/clientcaches

A user foo@EXAMPLE.COM delegating its credentials would cause the server to
create a ccache file named /var/run/httpd/clientcaches/foo@EXAMPLE.COM


### GssapiDelegCcacheUnique

Enables using unique ccache names for delegation.  ccache files will be placed
in GssapiDelegCcacheDir and named using the principal and a six-digit unique
suffix.

**Note:** Consuming application must delete the ccache otherwise it will
litter the filesystem if sessions are used.  An example sweeper can be found
in the contrib directory.  If using with gssproxy, see note at the top of that
file.

- **Enable with:** GssapiDelegCcacheUnique On
- **Default:** GssapiDelegCcacheUnique Off


### GssapiDelegCcacheEnvVar

Set the name of the request environment variable that will receive the
credential cache name.  If unspecified, defaults to `KRB5CCNAME`.

#### Example
    GssapiDelegCcacheEnvVar AJP_KRB5CCNAME


### GssapiUseS4U2Proxy

Enables the use of the s4u2Proxy Kerberos extension also known as
[constrained delegation](https://ssimo.org/blog/id_011.html)
This option allows an application running within Apache to operate on
behalf of the user against other servers by using the provided ticket
(subject to KDC authorization).
This options requires GssapiDelegCcacheDir to be set. The ccache will be
populated with the user's provided ticket which is later used as evidence
ticket by the application.

**Note:** This flag has no effect when Basic-Auth is used since user's
credentials are delegated anyway when GssapiDelegCcacheDir is set.

#### Example
    GssapiUseS4U2Proxy On
    GssapiCredStore keytab:/etc/httpd.keytab
    GssapiCredStore client_keytab:/etc/httpd.keytab
    GssapiCredStore ccache:FILE:/var/run/httpd/krb5ccache
    GssapiDelegCcacheDir /var/run/httpd/clientcaches

**NOTE:** The client keytab is necessary to allow GSSAPI to initiate via keytab
on its own. If not present an external mechanism needs to kinit with the
keytab and store a ccache in the configured ccache file.


### GssapiBasicAuth

Allows the use of Basic Auth in conjunction with Negotiate.
If the browser fails to use Negotiate it will instead fallback to Basic and
the username and password will be used to try to acquire credentials in the
module via GSSAPI. If credentials are acquired successfully then they are
validated against the server's keytab.

- **Enable with:** GssapiBasicAuth On
- **Default:** GssapiBasicAuth Off

#### Example
    <Location /gssapi>
      AuthType GSSAPI
      AuthName "Login"
      GssapiBasicAuth On
      GssapiCredStore keytab:/etc/httpd/http.keytab
      Require valid-user
    </Location>


### GssapiAllowedMech

List of allowed mechanisms. This is useful to restrict the mechanism that
can be used when credentials for multiple mechanisms are available.
By default no mechanism is set, this means all locally available mechanisms
are allowed.  The recognized mechanism names are: krb5, iakerb, ntlmssp

#### Example
    GssapiAllowedMech krb5
    GssapiAllowedMech ntlmssp


### GssapiBasicAuthMech

List of mechanisms against which Basic Auth is attempted. This is useful to
restrict the mechanisms that can be used to attempt password auth.
By default no mechanism is set, this means all locally available mechanisms
are allowed, unless GssapiAllowedMech is set, in which case those are used.
GssapiBasicAuthMech always takes precedence over GssapiAllowedMech.
The recognized mechanism names are: krb5, iakerb, ntlmssp

#### Example
    GssapiBasicAuthMech krb5


### GssapiNameAttributes

Enables the module to source Name Attributes from the client name
(authorization data associated with the established context) and exposes them
as environment variables.

Value format: ENV_VAR_NAME ATTRIBUTE_NAME

This option can be specified multiple times, once for each attribute to expose.
The Special value "json" is used to expose all attributes in a json formatted
string via the special environment variable GSS_NAME_ATTRS_JSON
The environment variable GSS_NAME_ATTR_ERROR is set with the Gssapi returned
error string in case the inquire name function fails to retrieve attributes,
and with the string "0 attributes found", if no attributes are set.

**Note**: These variables are NOT saved in the session data stored in the
cookie so they are available only on the first authenticated request when
GssapiUseSessions is used.

**Note:** It is recommended but not required to use only capital letters and
underscores for environment variable names.

#### Example
    GssapiNameAttributes json
    GssapiNameAttributes RADIUS_NAME urn:ietf:params:gss:radius-attribute_1


### GssapiRequiredNameAttributes

This option allows specifying one or more Name Attributes that the client must
possess in order to be authorized to access the location. The required Name
Attributes are specified by name=value pairs (name being the ATTRIBUTE_NAME as
mentioned above, and value being a Null-terminated string. Alternately, if a
Name Attribute produces binary values or is expected to contain a space
character, the desired value can be specified by a ':=' and a base64-encoded
string).

A combination of Name Attributes (including multiple values from a single Name
Attribute type) can be specified with an expression that separates each
name=value pair with the "and" or "or" logical operators.  Operator precedence
can be influenced by parenthesized statements.

	foo=bar
	foo:=YmFy
	foo=bar or foo=baz
	foo=bar and foo=baz and bar=baz
	(foo=bar and foo=baz) or bar:=YmFy

If the Name Attributes associated with the client do not satisfy the given
expression, or no Name Attributes are present, a 403 response is returned.

#### Example
    GssapiRequiredNameAttributes "auth-indicators=high"
    GssapiRequiredNameAttributes "auth-indicators=high or other-attr=foo"
    GssapiRequiredNameAttributes "((auth-indicators=low and auth-indicators=med) or auth-indicators=high)"


### GssapiNegotiateOnce

When this option is enabled the Negotiate header will not be resent if
Negotiation has already been attempted but failed.

Normally when a client fails to use Negotiate authentication, a HTTP 401
response is returned with a WWW-Authenticate: Negotiate header, implying that
the client can retry to use Negotiate with different credentials or a
different mechanism.

Consider enabling GssapiNegotiateOnce when only one single sign on mechanism
is allowed, or when GssapiBasicAuth is enabled.

**NOTE:** if the initial Negotiate attempt fails, some browsers will fallback
to other Negotiate mechanisms, prompting the user for login credentials and
reattempting negotiation. This situation can mislead users - for example if
krb5 authentication failed and no other mechanisms are allowed, a user could
be prompted for login information even though any login information provided
cannot succeed. When this occurs, some browsers will not fall back to a Basic
Auth mechanism. Enable GssapiNegotiateOnce to avoid this situation.

- **Enable with:** GssapiNegotiateOnce On
- **Default:** GssapiNegotiateOnce Off


### GssapiImpersonate

This option can be used even if AuthType GSSAPI is not used for given
Location or LocationMatch, to obtain service ticket for a user that was
already authenticated by different module.  (This is also known as s4u2self,
or protocol transition.)

The principal of the user is retrieved from the internal r->user
identifier which typically holds the username from the authentication
results.

Optionally, this user principal can later be used for s4u2proxy (constrained
delegation).  To do this, ensure the server principal is permitted to acquire
forwardable tickets to itself from arbitrary users (i.e., with the option
`+ok_to_auth_as_delegate`).

- **Enable with:** GssapiImpersonate On
- **Default:** GssapiImpersonate Off


### GssapiDelegCcachePerms

This option is used to set alternative ownership and permission for delegated
ccache files stored in the GssapiDelegCcacheDir location. It is a multivalue
configuration directive that can accept the following three settings:
- mode
- uid
- gid
If a setting is not present the relative file property will not be modified and
the default owners and/or mode will be retained.

#### mode
    This option allows to set the file mode, the format used is a numeric mode
    with the same semantics of the chmod unix command for mapping numbers to
    permissions.

#### uid
    A user id number or name, an attempt to change the user owner of the file
    to the uid number specified will be made. If a user name has been
    specified, it will be resolved at startup time and the user's id number
    stored internally for all subsequent operations.

#### gid
    A group id number or name, an attempt to change the group owner of the
    file to the gid number specified will be made. If a group name has been
    specified, it will be resolved at startup time and the group's id number
    stored internally for all subsequent operations.

#### Example
    GssapiDelegCcachePerms mode:0660 gid:webuiworkers


### GssapiPublishErrors

This option is used to publish errors as Environment Variables for use by
httpd processes.

A general error type is provided in the MAG_ERROR variable, and can have the
following values: "GSS ERROR", "INTERNAL ERROR", "AUTH NOT ALLOWED"
Additionally, in the variable named MAG_ERROR_TEXT there may be a free form
error message.

When the error type is "GSS ERROR" the variables GSS_ERROR_MAJ and
GSS_ERROR_MIN contain the numeric errors returned by GSSAPI, and the
MAG_ERROR_TEXT will contain a GSS Error message, possibly prepended by
an additional message that provides more context.

- **Enable with:** GssapiPublishErrors On
- **Default:** GssapiPublishErrors Off


### GssapiAcceptorName

This option is used to force the server to accept only for a specific name.

This allows, for example to select to use a specific credential when multiple
keys are provided in a keytab.

A special value of {HOSTNAME} will make the code use the name apache sees in
the httpd request to select the correct name to use. This may be useful to
allow multiple names and multiple keys to be used on the same apache instance.

Note: By default no name is set and any name in a keytab or mechanism specific
acceptor credential will be allowed.

Note: Global gssapi options set in krb5.conf like 'ignore_acceptor_hostname'
may affect the ability to restrict names.

Note: The GSS_C_NT_HOSTBASED_SERVICE format is used for names (see example).

#### Example
    GssapiAcceptorName HTTP@www.example.com


### GssapiBasicTicketTimeout

This option controls the ticket validity time requested for the user TGT by the
Basic Auth method.

Normally basic auth is repeated by the browser on each request so a short
validity period is used to reduce the scope of the ticket as it will be
replaced quickly.
However in cases where the authentication page is separate and the session
is used by other pages the validity can be changed to arbitrary duration.

Note: the validity of a ticket is still capped by KDC configuration.

Note: the value is specified in seconds.

- **Default:** GssapiBasicTicketTimeout 300

#### Example
    GssapiBasicTicketTimeout 36000

Sets ticket/session validity to 10 hours.


### GssapiPublishMech

This option is used to publish the mech used for authentication as an
Environment variable named GSS_MECH.

It will return a string of the form 'Authtype/Mechname'.
Authtype represents the type of auth performed by the module. Possible values
are 'Basic', 'Negotiate', 'NTLM', 'Impersonate'.
Mechname is the name of the mechanism as reported by GSSAPI or the OID of the
mechanism if a name is not available. In case of errors the 'Unavailable'
string may also be returned for either Authtype or Mechname.

- **Enable with:** GssapiPublishMech On
- **Default:** GssapiPublishMech Off
