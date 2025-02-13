rule Trojan_Linux_BlueShell_K_2147906329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/BlueShell.K!MTB"
        threat_id = "2147906329"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "BlueShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/tmp/.ICECache" ascii //weight: 10
        $x_10_2 = "/tmp/kthread" ascii //weight: 10
        $x_10_3 = "lgdt=" ascii //weight: 10
        $x_1_4 = "/usr/lib/systemd/systemd-udevd" ascii //weight: 1
        $x_1_5 = "/usr/libexec/rpciod" ascii //weight: 1
        $x_1_6 = "/usr/sbin/cron -f" ascii //weight: 1
        $x_1_7 = "/sbin/rpcd" ascii //weight: 1
        $x_1_8 = "/home/User/Desktop/client/main.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

