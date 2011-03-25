import MySQLdb, re, cjson

fields = (
        'Authority Information Access:1.3.6.1.4.4308.10.50 - URI',
        'fetchtime',
        'fingerprint',
        'id',
        'ip',
        'Issuer',
        'moz_valid',
        'ms_valid',
        'path',
        'RSA Public Key:Modulus',
        'RSA_Modulus_Bits',
        'Serial Number',
        'Signature',
        'Signature Algorithm',
        'Subject',
        'Subject Public Key Info:DSA Public Key:G',
        'Subject Public Key Info:DSA Public Key:P',
        'Subject Public Key Info:DSA Public Key:pub',
        'Subject Public Key Info:DSA Public Key:Q',
        'Subject Public Key Info:Public Key Algorithm',
        'Subject Public Key Info:RSA Public Key:Exponent',
        'transvalid',
        'valid',
        'Validity:Not After',
        'Validity:Not Before',
        'Version',
        'ext:Authority Information Access:CA Issuers - URI',
        'ext:Authority Information Access:OCSP - email',
        'ext:Authority Information Access:OCSP - URI',
        'ext:Netscape Base Url',
        'ext:Netscape CA Policy Url',
        'ext:Netscape CA Revocation Url',
        'ext:Netscape Cert Type',
        'ext:Netscape Comment',
        'ext:Netscape Renewal Url',
        'ext:Netscape Revocation Url',
        'ext:Netscape SSL Server Name',
        'ext:qcStatements',
        'ext:S/MIME Capabilities',
        'ext:setCext-hashedRoot',
        'ext:Subject Information Access:CA Repository - URI',
        'ext:Unknown',
        'ext:X509v3 Authority Key Identifier',
        'ext:X509v3 Authority Key Identifier:DirName',
        'ext:X509v3 Authority Key Identifier:keyid',
        'ext:X509v3 Authority Key Identifier:serial',
        'ext:X509v3 Basic Constraints:CA',
        'ext:X509v3 Certificate Policies',
        'ext:X509v3 Certificate Policies:Policy',
        'ext:X509v3 CRL Distribution Points',
        'ext:X509v3 Extended Key Usage',
        'ext:X509v3 Freshest CRL',
        'ext:X509v3 Issuer Alternative Name',
        'ext:X509v3 Key Usage',
        'ext:X509v3 Name Constraints',
        'ext:X509v3 Policy Mappings:2.16.756.1.83.0.1',
        'ext:X509v3 Private Key Usage Period:Not After',
        'ext:X509v3 Private Key Usage Period:Not Before',
        'ext:X509v3 Subject Alternative Name',
        'ext:X509v3 Subject Directory Attributes',
        'ext:X509v3 Subject Key Identifier',
        'X509v3 Policy Constraints:Require Explicit Policy',
        'X509v3 Policy Mappings:2.16.840.1.101.3.2.1.1.2',
        'X509v3 Policy Mappings:2.16.840.1.101.3.2.1.3.3',
        'nid',
        'startdate',
        'enddate',
        'fetchdatetime',
        'Validity:Not Before datetime',
        'Validity:Not After datetime')

def escape(field):
    if ' ' in field or ':' in field:
        return '`%s`' % field
    return field

query = 'select ' + \
        ','.join(map(escape, fields)) + \
        ' from valid_certs where fingerprint = %s;'

db = MySQLdb.connect(user="anon",passwd="",db="observatory")

def jsonify(o):
    if isinstance(o, str) or \
       isinstance(o, int) or \
       isinstance(o, float) or \
       isinstance(o, long):
        return o
    else:
        return str(o)

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
        c.execute(query, (fpstr,))
        r = c.fetchone()
        if r is None: raise Exception('query="%s" fpstr="%s"' % (query, fpstr))
        output = { }
        for i in xrange(len(fields)):
            if r[i] is not None:
                output[fields[i]] = jsonify(r[i])
        output = cjson.encode(output) + '\n'

        hdrs = [('Content-type', 'text/json'),
                ('Content-Length', str(len(output)))]
        start_response(status, hdrs)
        return [output]
    except Exception, e:
        output = "<html><body>'%s' not found</body></html>" % (fp,)
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

if __name__ == "__main__":
    def dump(result, headers):
        print result
        print headers
    print cmd_fingerprint(dump, ('a0027303726790e8a47264922f19c951334cc31a',))
