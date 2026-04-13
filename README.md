# UltimateAuth

UltimateAuth is a powerful and flexible authentication solution specifically designed for Minecraft servers, supporting both proxy (BungeeCord/Velocity) and game servers (Paper/Folia). Its purpose is to provide a secure, efficient, and easily manageable registration and login system, protecting your server from unauthorized access and enhancing the player experience.

With its separate two-component architecture, UltimateAuth ensures scalability, improved security, and a clear separation of responsibilities between the proxy and game layers.

## Key Features

UltimateAuth comes with a suite of advanced features to meet the authentication needs of modern Minecraft servers:

*   **Secure Password Management**: Utilizes modern cryptographic hashing algorithms (such as BCrypt or Argon2, depending on configuration) to store user passwords, ensuring that player credentials are well-protected even if the database is compromised.
*   **Mojang Premium Authentication**: Supports premium account verification via the Mojang API. Players with valid premium accounts can log in directly without needing to register or enter a password, providing a seamless and secure experience.
*   **Flexible Database Integration**: Compatible with various relational database systems (e.g., MySQL, SQLite) for persistent and reliable storage of account data. This allows you to choose the storage solution that best fits your infrastructure.
*   **JPremium Data Importer**: Facilitates the migration of user data from other popular authentication plugins like JPremium, enabling a smooth transition without losing existing player account data.
*   **Player Freezing**: A security mechanism that freezes newly joined or unauthenticated players. Players cannot move, interact, or send commands until they successfully register or log in, preventing abuse.
*   **Customizable Messages & Titles**: All messages displayed to players, including chat messages, titles, and subtitles, are fully customizable. This allows you to match the plugin's style and language with your server's branding.
*   **Extensive Configuration Options**: Provides a wide range of configuration options, allowing server administrators to fine-tune almost every aspect of the plugin's behavior, from security settings to user experience.
*   **Efficient Proxy-Backend Communication**: Both plugin components (proxy and backend) communicate efficiently to ensure a smooth authentication flow and synchronization of player status across your server network.

## Project Architecture

UltimateAuth is designed with a modular architecture consisting of two main components:

1.  **`ultimateauth-proxy` (Proxy Module)**:
    *   Runs on your proxy server (BungeeCord or Velocity).
    *   Responsible for handling all incoming player connections.
    *   Manages the registration and login processes.
    *   Interacts directly with the database to store and retrieve account data.
    *   Communicates with the Mojang API for premium account verification.
    *   Sends instructions and authentication status to the backend module on the game server.
    *   Manages player authentication sessions.

2.  **`ultimateauth-backend` (Backend Module)**:
    *   Runs on each of your Paper/Folia game servers.
    *   Receives instructions from the proxy module.
    *   Implements security actions such as freezing unauthenticated players.
    *   Displays local authentication messages and titles to players.
    *   Acts as a bridge between the proxy and specific game server functionalities.

**Simplified Authentication Flow:**

```
[Player] -- Joins --> [Proxy Server (ultimateauth-proxy)]
    |
    |-- Verify Premium Account (Mojang API)
    |-- Check Database (Account Data)
    |-- Registration/Login Process
    |
    V
[Game Server (ultimateauth-backend)] -- Instructions --> [Player (Freeze/Unfreeze)]
```

## System Requirements

To run UltimateAuth, you will need:

*   **Java Development Kit (JDK)**: Version 8 or newer.
*   **Apache Maven**: Version 3.x for building the project from source.
*   **Proxy Server**: BungeeCord or Velocity (latest versions recommended).
*   **Game Server**: Paper or Folia (latest versions recommended).
*   **Database**: MySQL (recommended) or SQLite.

## Installation Guide

Follow these steps to install and configure UltimateAuth:

### 1. Clone the Repository

First, clone the UltimateAuth repository to your local machine:

```bash
git clone https://github.com/your-username/UltimateAuth.git
cd UltimateAuth
```
*(Replace `your-username` with your GitHub username if you forked, or the official repository URL.)*

### 2. Build the Project

This project uses Apache Maven for dependency management and the build process. Run the following command in the project's root directory (`UltimateAuth/`):

```bash
mvn clean install
```
This command will compile the source code, run tests (if any), and package both modules into JAR files. You will find the generated JAR files in the `target/` directory of each sub-module:

*   `ultimateauth-backend/target/ultimateauth-backend-X.X.X-SNAPSHOT.jar`
*   `ultimateauth-proxy/target/ultimateauth-proxy-X.X.X-SNAPSHOT-shaded.jar`

### 3. Plugin Placement

After the build process is complete, you need to place the appropriate JAR files onto your servers:

*   **For Proxy Server (BungeeCord/Velocity)**:
    *   Copy `ultimateauth-proxy-X.X.X-SNAPSHOT-shaded.jar` to the `plugins/` folder on your proxy server.
*   **For Game Server (Paper/Folia)**:
    *   Copy `ultimateauth-backend-X.X.X-SNAPSHOT.jar` to the `plugins/` folder on each of your Paper/Folia game servers that you wish to protect.

### 4. Initial Configuration

Start your proxy server and game servers for the first time. This will generate configuration folders and files like `config.yml`, `messages.yml`, etc., inside the `plugins/UltimateAuth/` (for proxy) and `plugins/UltimateAuthBackend/` (for backend) folders.

**Important**: Shut down your servers after the configuration files are generated to proceed with the in-depth configuration step.

## In-Depth Configuration

UltimateAuth offers highly detailed configuration. It is crucial to review and adjust these files according to your server's specific needs.

### `ultimateauth-proxy/plugins/UltimateAuth/config.yml`

This is the main configuration file for the proxy module. Some important settings include:

*   **`storage`**: Database connection settings (type, host, port, user, password, database name).
*   **`authorization`**: Authentication mode (e.g., `PREMIUM_ONLY`, `CRACKED_ONLY`, `HYBRID`), login session settings, and login attempt limits.
*   **`premium`**: Settings related to Mojang API verification, profile caching, and failure handling.
*   **`network`**: Communication settings with the backend module, including a secret key for security.
*   **`file-import`**: Settings for importing data from other plugins (e.g., JPremium).

```yaml
# Example section from config.yml (ultimateauth-proxy)
storage:
  type: MYSQL # Or SQLITE
  mysql:
    host: localhost
    port: 3306
    database: ultimateauth
    username: user
    password: password
authorization:
  mode: HYBRID # PREMIUM_ONLY, CRACKED_ONLY, HYBRID
  session-duration-minutes: 1440 # 24 hours
premium:
  mojang-api-timeout-seconds: 5
  cache-duration-minutes: 60
network:
  secret-key: "ReplaceWithAStrongSecretKey" # VERY IMPORTANT TO CHANGE THIS!
```

### `ultimateauth-proxy/plugins/UltimateAuth/messages.yml`

This file contains all messages that players will see. You can change the text, colors, and formatting to match your server's theme.

```yaml
# Example section from messages.yml
messages:
  login-required: "&cYou must log in! Use /login <password>"
  register-required: "&aYou must register! Use /register <password> <password>"
  successful-login: "&aWelcome back, %player_name%!"
titles:
  login-title: "&6LOGIN"
  login-subtitle: "&fEnter your password"
```

### `ultimateauth-backend/plugins/UltimateAuthBackend/config.yml`

This configuration file is for the backend module on the game server. It primarily contains settings related to communication with the proxy and local behavior.

*   **`network`**: The same secret key as in `ultimateauth-proxy/config.yml` to ensure secure communication.
*   **`freeze`**: Settings related to player freezing (e.g., whether to freeze, messages displayed).

```yaml
# Example section from config.yml (ultimateauth-backend)
network:
  secret-key: "ReplaceWithAStrongSecretKey" # Must be the same as in the proxy!
freeze:
  enabled: true
  message: "&cYou are frozen until you log in!"
```

### `ultimateauth-proxy/bungee.yml` & `ultimateauth-backend/plugin.yml`

These files contain basic plugin metadata (name, version, author, dependencies). They typically do not need to be changed unless you want to modify the basic plugin information.

## Usage & Commands

After configuration, UltimateAuth will automatically manage player authentication.

*   **Premium Players**: If enabled, premium players will be automatically verified and logged in directly.
*   **Non-Premium/Cracked Players**:
    *   If not yet registered: Players will be prompted to register using `/register <password> <confirm_password>`.
    *   If already registered: Players will be prompted to log in using `/login <password>`.
*   **Admin Commands**: (If any, add them here. Example: `/auth reload`, `/auth unregister <player>`)

## Troubleshooting

*   **Plugin not loading**: Check server logs for error messages. Ensure you are using compatible Java and server versions.
*   **Cannot connect to database**: Check database credentials in the proxy's `config.yml`. Ensure the database server is running and accessible from the proxy machine.
*   **Players cannot log in/register**: Check the proxy's `config.yml` for the authentication mode (`HYBRID`, `PREMIUM_ONLY`, `CRACKED_ONLY`). Ensure the secret key in both the proxy and backend `config.yml` files are identical.
*   **Messages not appearing/incorrect**: Check `messages.yml` in the proxy and `config.yml` in the backend.

## Contributing

We highly appreciate contributions from the community! If you find a bug, have a feature suggestion, or wish to contribute code, please follow these steps:

1.  Fork this repository.
2.  Create a new branch for your feature or fix (`git checkout -b feature/your-feature-name` or `bugfix/your-fix-name`).
3.  Make your changes and commit (`git commit -m 'Add feature X'`).
4.  Push to your branch (`git push origin feature/your-feature-name`).
5.  Open a Pull Request to the main repository.

## License

This project is licensed under the [AllyncID, e.g., MIT License]. See the `LICENSE` file in the repository for more details.

---
*Made by Allync*
