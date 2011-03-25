import MySQLdb, re, cjson

'''
+---------------------------------------------------------+---------------+-----+
| Field                                                   | Type          | Key |
+---------------------------------------------------------+---------------+-----+
| Authority Information Access:1.3.6.1.4.4308.10.50 - URI | varchar(49)   |     |
| fetchtime                                               | int(11)       |     |
| fingerprint                                             | char(80)      | UNI |
| id                                                      | varchar(7)    |     |
| ip                                                      | varchar(15)   |     |
| Issuer                                                  | varchar(367)  |     |
| moz_valid                                               | varchar(401)  |     |
| ms_valid                                                | varchar(401)  |     |
| path                                                    | varchar(78)   |     |
| RSA Public Key:Modulus                                  | varchar(3074) |     |
| RSA_Modulus_Bits                                        | varchar(4)    |     |
| Serial Number                                           | varchar(59)   |     |
| Signature                                               | varchar(1535) |     |
| Signature Algorithm                                     | varchar(24)   |     |
| Subject                                                 | varchar(4513) |     |
| Subject Public Key Info:DSA Public Key:G                | varchar(386)  |     |
| Subject Public Key Info:DSA Public Key:P                | varchar(386)  |     |
| Subject Public Key Info:DSA Public Key:pub              | varchar(386)  |     |
| Subject Public Key Info:DSA Public Key:Q                | varchar(62)   |     |
| Subject Public Key Info:Public Key Algorithm            | varchar(14)   |     |
| Subject Public Key Info:RSA Public Key:Exponent         | varchar(24)   |     |
| transvalid                                              | varchar(3)    |     |
| valid                                                   | tinyint(1)    |     |
| Validity:Not After                                      | varchar(25)   |     |
| Validity:Not Before                                     | varchar(25)   |     |
| Version                                                 | varchar(8)    |     |
| ext:Authority Information Access:CA Issuers - URI       | varchar(509)  |     |
| ext:Authority Information Access:OCSP - email           | varchar(28)   |     |
| ext:Authority Information Access:OCSP - URI             | varchar(126)  |     |
| ext:Netscape Base Url                                   | varchar(29)   |     |
| ext:Netscape CA Policy Url                              | varchar(63)   |     |
| ext:Netscape CA Revocation Url                          | varchar(56)   |     |
| ext:Netscape Cert Type                                  | varchar(92)   |     |
| ext:Netscape Comment                                    | varchar(589)  |     |
| ext:Netscape Renewal Url                                | varchar(52)   |     |
| ext:Netscape Revocation Url                             | varchar(67)   |     |
| ext:Netscape SSL Server Name                            | varchar(19)   |     |
| ext:qcStatements                                        | varchar(48)   |     |
| ext:S/MIME Capabilities                                 | varchar(115)  |     |
| ext:setCext-hashedRoot                                  | varchar(57)   |     |
| ext:Subject Information Access:CA Repository - URI      | varchar(256)  |     |
| ext:Unknown                                             | varchar(559)  |     |
| ext:X509v3 Authority Key Identifier                     | varchar(2)    |     |
| ext:X509v3 Authority Key Identifier:DirName             | varchar(228)  |     |
| ext:X509v3 Authority Key Identifier:keyid               | varchar(127)  |     |
| ext:X509v3 Authority Key Identifier:serial              | varchar(59)   |     |
| ext:X509v3 Basic Constraints:CA                         | varchar(41)   |     |
| ext:X509v3 Certificate Policies                         | varchar(111)  |     |
| ext:X509v3 Certificate Policies:Policy                  | varchar(1045) |     |
| ext:X509v3 CRL Distribution Points                      | blob          |     |
| ext:X509v3 Extended Key Usage                           | varchar(693)  |     |
| ext:X509v3 Freshest CRL                                 | varchar(184)  |     |
| ext:X509v3 Issuer Alternative Name                      | varchar(198)  |     |
| ext:X509v3 Key Usage                                    | varchar(144)  |     |
| ext:X509v3 Name Constraints                             | varchar(599)  |     |
| ext:X509v3 Policy Mappings:2.16.756.1.83.0.1            | varchar(17)   |     |
| ext:X509v3 Private Key Usage Period:Not After           | varchar(25)   |     |
| ext:X509v3 Private Key Usage Period:Not Before          | varchar(62)   |     |
| ext:X509v3 Subject Alternative Name                     | varchar(7761) |     |
| ext:X509v3 Subject Directory Attributes                 | varchar(77)   |     |
| ext:X509v3 Subject Key Identifier                       | varchar(127)  |     |
| X509v3 Policy Constraints:Require Explicit Policy       | varchar(12)   |     |
| X509v3 Policy Mappings:2.16.840.1.101.3.2.1.1.2         | varchar(228)  |     |
| X509v3 Policy Mappings:2.16.840.1.101.3.2.1.3.3         | varchar(232)  |     |
| nid                                                     | int(11)       | PRI |
| startdate                                               | datetime      |     |
| enddate                                                 | datetime      |     |
| fetchdatetime                                           | datetime      |     |
| Validity:Not Before datetime                            | datetime      |     |
| Validity:Not After datetime                             | datetime      |     |
+---------------------------------------------------------+---------------+-----+
'''

db = MySQLdb.connect(user="anon",passwd="",db="observatory")

def cmd_fingerprint(start_response, args):
    fp = ''
    try:
        status = '200 OK'

        pat = '^' + ( '([0-9a-fA-F][0-9a-fA-F])' * 20) + '$'
        fp = args[0]
        fp = re.match(pat, fp)
        if fp is None: raise Exception("pat = '%s' fp='%s'" % (pat, args[0]))
        fp = (':'.join([fp.group(i) for i in xrange(1,21)])).upper()
        fpstr = "SHA1 Fingerprint=" + fp
        c = db.cursor()
        query = 'select fetchtime, id, Issuer, startdate, enddate, ' + \
                '`Serial Number`, Version, `ext:X509v3 Key Usage` from ' + \
                'valid_certs where fingerprint = %s;'
        c.execute(query, (fpstr,))
        r = c.fetchone()
        if r is None: raise Exception('query="%s" fpstr="%s"' % (query, fpstr))
        output = { "fingerprint": fp,
                   "fetchtime": str(r[0]),
                   "id":        str(r[1]),
                   "Issuer":    str(r[2]),
                   "startdate": str(r[3]),
                   "enddate":   str(r[4]),
                   "Serial Number": str(r[5]),
                   "Version":   str(r[6]),
                   "ext:X509v3 Key Usage": str(r[7]) }
        output = cjson.encode(output)

        hdrs = [('Content-type', 'text/json'),
                ('Content-Length', str(len(output)))]
        start_response(status, hdrs)
        return [output]
    except Exception, e:
        output = "<html><body>'%s' not found: %r</body></html>" % (fp, e)
        hdrs = [('Content-type', 'text/html'),
                ('Content-Length', str(len(output)))]
        start_response('404 Not Found', hdrs)
        return [output]


def cmd_commonname(start_response, args):
    status = '404 Not Found'
    output = '/cn/ not implemented yet'

    hdrs = [('Content-type', 'text/plain'),
            ('Content-Length', str(len(output)))]
    start_response(status, hdrs)
    return [output]

def application(environ, start_response):
    status = '404 Not Found'
    uri = environ['REQUEST_URI']
    uri = uri.split('/')
    cmd = uri[2]

    if cmd == 'fp':
        return cmd_fingerprint(start_response, uri[3:])
    elif cmd == 'cn':
        return cmd_commonname(start_response, uri[2:])
    else:
        output = 'The method "%s" was not found' % cmd
        hdrs = [('Content-type', 'text/plain'),
                ('Content-Length', str(len(output)))]
        start_response(status, hdrs)
        return [output]
