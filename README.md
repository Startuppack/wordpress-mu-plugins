# wordpress-mu-plugins

Must-use WordPress plugins **développés par l'équipe Startup Pack**, déployés sur
TOUS les WordPress tenants. Clonés au démarrage du pod (init container
`install-mu-plugin`) dans `wp-content/mu-plugins/` → force-actifs, non
désactivables par le client.

À ne pas confondre avec les plugins **du client** (dépôt Forgejo
`<client>/wordpress-plugins`), qui vont dans `wp-content/plugins/` (activables).

## Contenu
- `mu-plugins/keycloak-sso.php` — SSO OIDC Keycloak (bouton login, callback,
  mapping rôles via `resource_access.wordpress.roles`, logout fédéré, SMTP).
  Config 100 % par **variables d'environnement** (`OIDC_KC_BASE`,
  `OIDC_CLIENT_SECRET`, `LOGOUT_DONE_URL`, `SMTP_*`) — aucun secret dans le code.

## Déploiement
Le chart `dna-platform` (template `wordpress.yaml`) clone ce dépôt au boot :
`git clone --depth 1 --branch main https://github.com/Startuppack/wordpress-mu-plugins.git`
puis copie `mu-plugins/.` dans `wp-content/mu-plugins/`. Repo/branche
surchargeables via `wordpress.muPluginsRepo` / `wordpress.muPluginsRef`.
