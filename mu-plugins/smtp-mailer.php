<?php
/**
 * Plugin Name: Startuppack SMTP Mailer
 * Description: Route wp_mail() through the tenant SMTP relay (self-hosted Postal)
 *              using the SMTP_* env vars injected by the dna-platform chart
 *              (helper "dna.smtpEnv"). Sans SMTP_HOST provisionné, on ne touche
 *              à rien (WP garde son comportement mail() par défaut).
 * Author: Startup Pack
 * Version: 1.0.0
 */

if (!defined('ABSPATH')) {
    exit;
}

add_action('phpmailer_init', function ($phpmailer) {
    $host = getenv('SMTP_HOST');
    if (!$host) {
        return; // pas encore email-provisionné → ne rien forcer
    }
    $phpmailer->isSMTP();
    $phpmailer->Host       = $host;
    $phpmailer->Port       = (int) (getenv('SMTP_PORT') ?: 2525);

    $user = getenv('SMTP_USERNAME');
    $pass = getenv('SMTP_PASSWORD');
    if ($user) {
        // Postal EXIGE AUTH PLAIN (sinon « 530 Authentication required »).
        $phpmailer->SMTPAuth = true;
        $phpmailer->Username = $user;
        $phpmailer->Password = $pass;
    }

    // STARTTLS sur le port de soumission ; cert Postal auto-signé en interne
    // cluster → on accepte le cert invalide (trafic privé).
    $phpmailer->SMTPSecure  = 'tls';
    $phpmailer->SMTPAutoTLS = true;
    $phpmailer->SMTPOptions = array(
        'ssl' => array(
            'verify_peer'       => false,
            'verify_peer_name'  => false,
            'allow_self_signed' => true,
        ),
    );
}, 20);

// From par défaut = adresse de relais du tenant (domaine autorisé côté Postal).
add_filter('wp_mail_from', function ($from) {
    $env = getenv('SMTP_FROM_ADDRESS');
    return $env ?: $from;
}, 20);

add_filter('wp_mail_from_name', function ($name) {
    $env = getenv('SMTP_FROM_NAME');
    return $env ?: $name;
}, 20);
