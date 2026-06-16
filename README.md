(STUFF IS GETTING NUKED CUS I'M DAEMONIZING IT)

### Requirements:
- Linux with PAM
- libpam development headers
- Rust toolchain
- gatekeeper-core
- If NFC stuff breaks, try building these variations locally: 
  * [libfreefare-0.4.0](https://github.com/nfc-tools/libfreefare/releases/tag/libfreefare-0.4.0)
  * [libnfc 1.8.0](https://github.com/nfc-tools/libnfc/releases/download/libnfc-1.8.0/libnfc-1.8.0.tar.bz2)

### Setup:
- ``cargo build``
- ``sudo cp target/debug/libgatekeeper_pam.so /usr/lib64/security/libgatekeeper_pam.so``
- Create ``/etc/gatekeeper-pam.conf`` to store env(s)
- ``sudo chmod 600 /etc/gatekeeper-pam.conf`` ``sudo chown root:root /etc/gatekeeper-pam.conf`` (sensitive stuff)
- Edit ``/etc/pam.d/gdm-password`` and add the module as ``sufficient``
- If SELinux is enforcing denials, create a single policy module granting permissions needed for serial device access (WIP for a better solution)
