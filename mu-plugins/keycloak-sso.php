<?php
/**
 * Plugin Name: External OIDC SSO
 */
if (!defined('ABSPATH')) exit;

define('OIDC_KC_BASE', getenv('OIDC_KC_BASE') ?: '');
define('OIDC_CLIENT_ID', getenv('OIDC_CLIENT_ID') ?: 'wordpress');
define('OIDC_CLIENT_SECRET', getenv('OIDC_CLIENT_SECRET') ?: '');
// Page d'atterrissage unifiée post-déconnexion (SPA onboarding). Surchargée
// via l'env LOGOUT_DONE_URL ; défaut = la plateforme partagée.
define('OIDC_LOGOUT_DONE', getenv('LOGOUT_DONE_URL') ?: 'https://platform.startuppack.eu/logoutalltools');

function oidc_callback_url() {
    return site_url('/wp-login.php?action=oidc_callback');
}

// ── OIDC Back-Channel Logout : helpers de vérif du logout_token (JWT RS256
//    signé par Keycloak). WordPress n'embarque pas de lib JWT → on vérifie la
//    signature à la main via JWKS + openssl (clé RSA reconstruite depuis n/e).
function oidc_b64url_decode($d) {
    return base64_decode(strtr($d, '-_', '+/') . str_repeat('=', (4 - strlen($d) % 4) % 4));
}
function oidc_der_len($n) {
    if ($n < 0x80) return chr($n);
    $b = ltrim(pack('N', $n), "\x00");
    return chr(0x80 | strlen($b)) . $b;
}
function oidc_jwk_to_pem($n_b64, $e_b64) {
    $n = oidc_b64url_decode($n_b64); $e = oidc_b64url_decode($e_b64);
    $int = function($x) {
        if (ord($x[0]) > 0x7f) $x = "\x00" . $x;
        return "\x02" . oidc_der_len(strlen($x)) . $x;
    };
    $seq = $int($n) . $int($e);
    $rsa = "\x30" . oidc_der_len(strlen($seq)) . $seq;            // RSAPublicKey
    $bit = "\x03" . oidc_der_len(strlen($rsa) + 1) . "\x00" . $rsa; // BIT STRING
    $oid = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";
    $spki = $oid . $bit;
    $der = "\x30" . oidc_der_len(strlen($spki)) . $spki;          // SubjectPublicKeyInfo
    return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
}
function oidc_verify_logout_token($jwt) {
    $parts = explode('.', $jwt);
    if (count($parts) !== 3) return false;
    list($h64, $p64, $s64) = $parts;
    $header  = json_decode(oidc_b64url_decode($h64), true);
    $payload = json_decode(oidc_b64url_decode($p64), true);
    if (!$header || !$payload || ($header['alg'] ?? '') !== 'RS256') return false;
    $kid = $header['kid'] ?? '';
    $jwks = get_transient('oidc_jwks');
    if (!$jwks) {
        $resp = wp_remote_get(OIDC_KC_BASE . '/certs', ['timeout' => 10, 'sslverify' => false]);
        if (is_wp_error($resp)) return false;
        $jwks = json_decode(wp_remote_retrieve_body($resp), true);
        if (empty($jwks['keys'])) return false;
        set_transient('oidc_jwks', $jwks, HOUR_IN_SECONDS);
    }
    $jwk = null;
    foreach ($jwks['keys'] as $k) {
        if (($k['kid'] ?? '') === $kid && ($k['kty'] ?? '') === 'RSA') { $jwk = $k; break; }
    }
    if (!$jwk) return false;
    $pem = oidc_jwk_to_pem($jwk['n'], $jwk['e']);
    if (openssl_verify("$h64.$p64", oidc_b64url_decode($s64), $pem, OPENSSL_ALGO_SHA256) !== 1) return false;
    // Claims : iss (realm), aud/azp = ce client, et l'évènement BCL.
    $issuer = preg_replace('#/protocol/openid-connect$#', '', OIDC_KC_BASE);
    if (($payload['iss'] ?? '') !== $issuer) return false;
    $aud = $payload['aud'] ?? '';
    $aud_ok = (is_array($aud) ? in_array(OIDC_CLIENT_ID, $aud, true) : $aud === OIDC_CLIENT_ID)
              || (($payload['azp'] ?? '') === OIDC_CLIENT_ID);
    if (!$aud_ok) return false;
    if (!isset($payload['events']['http://schemas.openid.net/event/backchannel-logout'])) return false;
    return $payload;
}

// Endpoint Back-Channel Logout : Keycloak POSTe le logout_token ici quand la
// session SSO se termine → on tue la session WordPress de l'utilisateur CÔTÉ
// SERVEUR (vraie déconnexion IdP-initiée, indépendante du RP-logout WP).
add_action('login_init', function() {
    if (($_GET['action'] ?? '') !== 'oidc_backchannel_logout') return;
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') { status_header(405); exit; }
    $claims = oidc_verify_logout_token($_POST['logout_token'] ?? '');
    if (!$claims) { status_header(400); echo 'invalid logout_token'; exit; }
    $killed = 0;
    $targets = [];
    if (!empty($claims['sid'])) $targets[] = ['oidc_sid', $claims['sid']];
    if (!empty($claims['sub'])) $targets[] = ['oidc_sub', $claims['sub']];
    foreach ($targets as $t) {
        foreach (get_users(['meta_key' => $t[0], 'meta_value' => $t[1], 'fields' => 'ID']) as $uid) {
            WP_Session_Tokens::get_instance($uid)->destroy_all();
            $killed++;
        }
    }
    status_header(200);
    header('Content-Type: application/json');
    echo json_encode(['logged_out' => $killed]);
    exit;
}, 1);

// SSO strict : auto-redirect vers Keycloak. Le formulaire user/pass
// local n'est jamais rendu. Les POST directs (curl etc.) sont rejetés
// par défense en profondeur.
add_action('login_init', function() {
    $action = $_GET['action'] ?? '';
    // Pass-through pour le callback OIDC et la sortie de session
    if (in_array($action, ['oidc_callback', 'logout', 'loggedout', 'oidc_backchannel_logout'], true)) return;
    // Bloque les soumissions password locales
    if (!empty($_POST['log']) || !empty($_POST['pwd'])) {
        wp_die('Local login disabled. Use SSO only.', 'SSO required',
               ['response' => 403]);
    }
    // GET sur wp-login.php → redirige immédiatement vers Keycloak
    if ($_SERVER['REQUEST_METHOD'] === 'GET' && in_array($action, ['', 'login'], true)) {
        $auth_url = OIDC_KC_BASE . '/auth?' . http_build_query([
            'client_id'     => OIDC_CLIENT_ID,
            'redirect_uri'  => oidc_callback_url(),
            'response_type' => 'code',
            'scope'         => 'openid email profile',
            'state'         => wp_create_nonce('oidc_state'),
        ]);
        wp_redirect($auth_url);
        exit;
    }
}, 1);

add_action('login_init', function() {
    if (!isset($_GET['action']) || $_GET['action'] !== 'oidc_callback') return;
    if (empty($_GET['code'])) wp_die('Missing authorization code');

    $token_resp = wp_remote_post(OIDC_KC_BASE . '/token', [
        'body' => [
            'grant_type' => 'authorization_code',
            'client_id' => OIDC_CLIENT_ID,
            'client_secret' => OIDC_CLIENT_SECRET,
            'redirect_uri' => oidc_callback_url(),
            'code' => sanitize_text_field($_GET['code']),
        ],
        'timeout' => 30,
        'sslverify' => false,
    ]);
    if (is_wp_error($token_resp)) wp_die('Token error: ' . $token_resp->get_error_message());

    $tokens = json_decode(wp_remote_retrieve_body($token_resp), true);
    if (empty($tokens['access_token'])) wp_die('No access token');

    $info_resp = wp_remote_get(OIDC_KC_BASE . '/userinfo', [
        'headers' => ['Authorization' => 'Bearer ' . $tokens['access_token']],
        'timeout' => 15,
        'sslverify' => false,
    ]);
    if (is_wp_error($info_resp)) wp_die('Userinfo error: ' . $info_resp->get_error_message());

    $info = json_decode(wp_remote_retrieve_body($info_resp), true);
    $email = sanitize_email($info['email'] ?? '');
    $username = sanitize_user($info['preferred_username'] ?? $email);
    if (empty($email)) wp_die('No email in user info');

    $user = get_user_by('email', $email);
    if (!$user) {
        $user_id = wp_insert_user([
            'user_login' => $username,
            'user_email' => $email,
            'user_pass' => wp_generate_password(32),
            'first_name' => $info['given_name'] ?? '',
            'last_name' => $info['family_name'] ?? '',
            'role' => 'administrator',
        ]);
        if (is_wp_error($user_id)) wp_die('User creation failed: ' . $user_id->get_error_message());
        $user = get_user_by('id', $user_id);
    }

    // Mémorise l'id_token pour le RP-initiated logout : passé en id_token_hint
    // au end-session Keycloak, il évite la page de confirmation KC (« Do you
    // want to log out? ») et permet la redirection directe vers /logoutalltools.
    if (!empty($tokens['id_token'])) {
        update_user_meta($user->ID, 'oidc_id_token', $tokens['id_token']);
        // Mémorise sub + sid (claims de l'id_token) pour le Back-Channel Logout :
        // KC envoie un logout_token portant sub/sid → on retrouve l'user WP par
        // ces meta pour tuer sa session côté serveur.
        $idp = explode('.', $tokens['id_token']);
        if (count($idp) === 3) {
            $c = json_decode(oidc_b64url_decode($idp[1]), true) ?: [];
            if (!empty($c['sub'])) update_user_meta($user->ID, 'oidc_sub', $c['sub']);
            if (!empty($c['sid'])) update_user_meta($user->ID, 'oidc_sid', $c['sid']);
        }
    }
    wp_set_auth_cookie($user->ID, true);
    wp_redirect(admin_url());
    exit;
});

// RP-initiated logout : à la déconnexion WordPress, on tue AUSSI la session
// Keycloak (sinon la prochaine visite re-logue en SSO sans rien demander) et
// on atterrit sur la page unifiée /logoutalltools de la plateforme. Sans
// post_logout_redirect_uri whitelisté côté client KC (cf. oidc-init :
// post.logout.redirect.uris), Keycloak refuserait la redirection.
add_action('wp_logout', function($user_id = 0) {
    $params = ['post_logout_redirect_uri' => OIDC_LOGOUT_DONE];
    $idt = $user_id ? get_user_meta($user_id, 'oidc_id_token', true) : '';
    if ($idt) {
        // id_token_hint → Keycloak redirige direct (pas de page de confirmation).
        $params['id_token_hint'] = $idt;
        delete_user_meta($user_id, 'oidc_id_token');
    } else {
        $params['client_id'] = OIDC_CLIENT_ID;
    }
    $end = OIDC_KC_BASE . '/logout?' . http_build_query($params);
    wp_redirect($end);
    exit;
}, 99);

// SMTP via Postal — credentials lus du Secret <slug>-smtp-secret (env vars
// SMTP_HOST/PORT/USERNAME/PASSWORD/FROM_ADDRESS/FROM_NAME, optional=true).
// Si SMTP_HOST est vide, on n'enregistre PAS les hooks → WordPress utilise
// mail() (qui échoue silencieusement) plutôt que de crash sur PHPMailer.
if (getenv('SMTP_HOST')) {
    add_action('phpmailer_init', function ($mailer) {
        $mailer->isSMTP();
        $mailer->Host       = getenv('SMTP_HOST');
        $mailer->Port       = (int) (getenv('SMTP_PORT') ?: 25);
        $mailer->SMTPAuth   = (bool) getenv('SMTP_USERNAME');
        $mailer->Username   = getenv('SMTP_USERNAME');
        $mailer->Password   = getenv('SMTP_PASSWORD');
        $mailer->SMTPSecure = 'tls';   // STARTTLS — Postal accepte
        $mailer->From       = getenv('SMTP_FROM_ADDRESS') ?: $mailer->From;
        $mailer->FromName   = getenv('SMTP_FROM_NAME') ?: $mailer->FromName;
    });
    add_filter('wp_mail_from',      function ($e) { return getenv('SMTP_FROM_ADDRESS') ?: $e; });
    add_filter('wp_mail_from_name', function ($n) { return getenv('SMTP_FROM_NAME') ?: $n; });
}
