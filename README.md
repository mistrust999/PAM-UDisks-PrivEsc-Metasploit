# CVE-2025-6018 & CVE-2025-6019 Metasploit Modules

This repository provides two Metasploit Framework exploit modules designed to exploit the vulnerabilities CVE-2025-6018 and CVE-2025-6019 discovered by Qualys:

* **CVE-2025-6018**: Privilege escalation from an unprivileged SSH user to a polkit "allow\_active" user via PAM environment manipulation on openSUSE Leap 15 and SUSE Linux Enterprise 15.

* **CVE-2025-6019**: Privilege escalation from a polkit "allow\_active" user to full root access via a vulnerable filesystem resize operation provided by `libblockdev` through the `udisks` daemon.

## Usage

1. **Place Modules into Metasploit:**

Copy both `.rb` exploit module files into your Metasploit modules directory:

```bash
~/.msf4/modules/exploits/linux/local/
```

2. **Reload Metasploit modules:**

In Metasploit console:

```bash
msf > reload_all
```

3. **Exploit:**

* Start a session on the vulnerable host.
* Run CVE-2025-6018 module first to escalate to "allow\_active" privileges.
* Run CVE-2025-6019 module next to escalate to full root privileges.

## Example Execution

Within a Metasploit session:

```bash
use exploit/linux/local/opensuse_suse_pam_env
run
# Follow instructions to establish allow_active privileges

use exploit/linux/local/udisks_libblockdev_xfs_resize
run
# Gain full root shell
```

## Important Notes

* **CVE-2025-6018:** Requires user re-login or a new SSH session to activate.
* **CVE-2025-6019:** Requires "allow\_active" user privileges, achievable via CVE-2025-6018 or similar vulnerabilities.

## Credits

Original discovery and detailed analysis by [Qualys Security Advisory](https://www.qualys.com).

This is the link to Qualys' original [Proof of Concept](https://cdn2.qualys.com/2025/06/17/suse15-pam-udisks-lpe.txt)

## Disclaimer

These modules are provided for educational and ethical penetration testing purposes only. Unauthorized use is strictly prohibited.
