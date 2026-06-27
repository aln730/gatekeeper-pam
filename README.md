## Gatekeeper PAM
A Linux PAM module enabling NFC-based authentication using the Gatekeeper API
- Centralized Authentication: identity resolved via LDAP-backed lookup, no per-machine config files
- Daemon/Socket Architecture: gatekeeperd holds exclusive control of the NFC hardware and API calls. The PAM module only talks to it over a socket
- DESFire AES-128 mutual authentication, not raw UID matching
- SELinux + Systemd Hardened: serial device policy at lock screen, hardened service unit (WIP)

### Requirements:
- Linux with PAM
- libpam development headers
- Rust toolchain
- gatekeeper-core
- PN532 NFC reader over UART
- If NFC stuff breaks, try building these variations locally: 
  * [libfreefare-0.4.0](https://github.com/nfc-tools/libfreefare/releases/tag/libfreefare-0.4.0)
  * [libnfc 1.8.0](https://github.com/nfc-tools/libnfc/releases/download/libnfc-1.8.0/libnfc-1.8.0.tar.bz2)

### Setup:
- ``cargo build``
- ``sudo cp target/debug/libgatekeeper_pam.so /usr/lib64/security/libgatekeeper_pam.so``
- Create ``/etc/gatekeeper-pam.conf`` to store env(s)
- ``sudo chmod 600 /etc/gatekeeper-pam.conf`` ``sudo chown root:root /etc/gatekeeper-pam.conf`` (sensitive stuff)
- Create a service account with serial device access
- Create the systemd service
- - Edit ``/etc/pam.d/gdm-password`` and add the module as ``sufficient`` (or whichever service you want to protect)
- If SELinux is enforcing denials, create a single policy module granting permissions needed for serial device access (WIP for a better solution)
- X11 only: disable DPMS

### Limitations:
- Needs internet for uid lookup (Can fallback to password authentication. Keys could be cached in the future)

### To-Do
- Find a secure workaround for keyring
- Make it even more easier to setup the stuff using a script
- Maybe offline mode
