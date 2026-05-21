import requests
import json
from urllib.parse import urljoin

class GraphQLScanner:
    def __init__(self, url, args):
        self.url = url.rstrip('/')
        self.args = args
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
            'Content-Type': 'application/json'
        })
        
        if args.proxy:
            self.session.proxies = {'http': args.proxy, 'https': args.proxy}
        
        self.results = []
        self.graphql_endpoints = []
    
    def discover_endpoints(self):
        """Discover GraphQL endpoints"""
        common_paths = [
            '/graphql', '/graphiql', '/graphql/console', '/graphql.php',
            '/api/graphql', '/api/v1/graphql', '/api/v2/graphql',
            '/graphql/v1', '/gql', '/query',
            '/admin/graphql', '/api/graphiql',
            '/graphql?query=', '/graphql/explorer',
            '/graphql-playground', '/playground'
        ]
        
        endpoints = []
        for path in common_paths:
            test_url = urljoin(self.url, path)
            endpoints.append(test_url)
        
        return endpoints
    
    def test_introspection(self, endpoint):
        """Test if GraphQL introspection is enabled"""
        introspection_query = {
            "query": """
                query IntrospectionQuery {
                    __schema {
                        types {
                            name
                            kind
                            description
                            fields {
                                name
                                type {
                                    name
                                    kind
                                    ofType {
                                        name
                                        kind
                                    }
                                }
                            }
                        }
                    }
                }
            """
        }
        
        try:
            response = self.session.post(
                endpoint,
                json=introspection_query,
                timeout=self.args.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'data' in data and '__schema' in data['data']:
                    schema = data['data']['__schema']
                    type_count = len(schema.get('types', []))
                    
                    # Extract all query/mutation names
                    query_types = []
                    for t in schema.get('types', []):
                        if t.get('name') and not t['name'].startswith('__'):
                            query_types.append(t['name'])
                    
                    self.results.append({
                        'url': endpoint,
                        'technique': 'GraphQL Introspection Enabled',
                        'severity': 'High',
                        'evidence': f"Schema exposed with {type_count} types",
                        'detail': f"Query types available: {', '.join(query_types[:10])}",
                        'remediation': 'Disable introspection in production environments'
                    })
                    return True
                    
        except Exception:
            pass
        
        return False
    
    def test_batch_attack(self, endpoint):
        """Test for batch query DoS potential"""
        # Send a deep nested query
        deep_query = {
            "query": """
                query {
                    __typename
                    "a": __typename
                    "b": __typename
                    "c": __typename
                    "d": __typename
                    "e": __typename
                    "f": __typename
                    "g": __typename
                    "h": __typename
                    "i": __typename
                    "j": __typename
                }
            """
        }
        
        try:
            response = self.session.post(
                endpoint,
                json=deep_query,
                timeout=5
            )
            
            if response.status_code == 200:
                # If server handles it fine, check if there's rate limiting
                for i in range(10):
                    self.session.post(endpoint, json=deep_query, timeout=5)
                
                self.results.append({
                    'url': endpoint,
                    'technique': 'GraphQL - Batching/Rate Limiting Check',
                    'severity': 'Info',
                    'evidence': '10 rapid queries all returned 200',
                    'detail': 'Server may allow batch queries without rate limiting',
                    'remediation': 'Implement query depth limiting and rate limiting'
                })
        except Exception:
            pass
    
    def test_unauthorized_query(self, endpoint):
        """Test for unauthorized query access"""
        # Try common sensitive queries
        test_queries = [
            {"query": "{ users { id username email password role } }"},
            {"query": "{ admin { secretKey credentials } }"},
            {"query": "{ config { apiKeys database password } }"},
            {"query": "{ __schema { types { name fields { name } } } }"},
            {"query": "mutation { login(password: \"test\", email: \"test\") { token } }"},
        ]
        
        for query in test_queries:
            try:
                response = self.session.post(endpoint, json=query, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    if 'data' in data and data['data']:
                        # Got data back - might be unauthorized access
                        key = list(data['data'].keys())[0]
                        if data['data'][key]:
                            self.results.append({
                                'url': endpoint,
                                'technique': f'GraphQL - Unauthorized Query',
                                'severity': 'High' if 'password' in str(query) or 'secret' in str(query) else 'Medium',
                                'evidence': f"Query '{key}' returned data without auth",
                                'detail': f"Query: {str(query)[:80]}",
                                'remediation': 'Implement proper authentication and authorization checks on all queries'
                            })
                            return
            except Exception:
                continue
    
    def test_schema_disclosure(self, endpoint):
        """Test for schema disclosure via errors"""
        # Malformed query to trigger error with schema info
        malformed_queries = [
            {"query": "{ "},
            {"query": "invalid syntax"},
            {"query": "{ nonExistentField }"},
            {"query": "{ user(id: \"abc\") { invalidField } }"},
        ]
        
        for query in malformed_queries:
            try:
                response = self.session.post(endpoint, json=query, timeout=5)
                if response.status_code in [400, 500]:
                    text = response.text
                    if '"errors"' in text and ('"message"' in text or '"locations"' in text):
                        self.results.append({
                            'url': endpoint,
                            'technique': 'GraphQL - Schema Disclosure via Errors',
                            'severity': 'Low',
                            'evidence': 'Error messages may reveal schema information',
                            'detail': f'Error query: {str(query)[:60]}',
                            'remediation': 'Use generic error messages in production'
                        })
                        return
            except Exception:
                continue
    
    def scan(self):
        """Main GraphQL scan"""
        print("    [*] Discovering GraphQL endpoints...")
        
        endpoints = self.discover_endpoints()
        
        for endpoint in endpoints:
            try:
                # Quick check if endpoint exists
                response = self.session.get(endpoint, timeout=3)
                if response.status_code != 404:
                    self.graphql_endpoints.append(endpoint)
                    print(f"    [*] Found GraphQL endpoint: {endpoint}")
            except:
                continue
        
        if not self.graphql_endpoints:
            print("    [!] No GraphQL endpoints discovered")
            return self.results
        
        for endpoint in self.graphql_endpoints:
            print(f"    [*] Testing: {endpoint}")
            
            # Test introspection
            print("    [*] Testing introspection...")
            if self.test_introspection(endpoint):
                print(f"    [!] Introspection is ENABLED - full schema exposed!")
            
            # Test unauthorized queries
            print("    [*] Testing unauthorized access...")
            self.test_unauthorized_query(endpoint)
            
            # Test batch/Dos
            print("    [*] Testing batch query handling...")
            self.test_batch_attack(endpoint)
            
            # Test schema disclosure
            self.test_schema_disclosure(endpoint)
        
        if self.results:
            print(f"\n    [!] Found {len(self.results)} GraphQL issues")
            for r in self.results:
                print(f"    {'🚨' if r.get('severity') == 'High' else '⚠️'} [{r.get('severity','Info')}] {r['technique']}")
        else:
            print("    [+] No GraphQL vulnerabilities detected")
        
        return self.results