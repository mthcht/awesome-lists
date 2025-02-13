rule Trojan_Linux_Xorddos_A_2147793901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Xorddos.A!xp"
        threat_id = "2147793901"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Xorddos"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/etc/rc.d/rc%d.d/S90" ascii //weight: 1
        $x_1_2 = "sed -i '/\\/etc\\/cron." ascii //weight: 1
        $x_1_3 = {c7 04 24 98 f9 0a 08 e8 fa 87 00 00 81 c4 2c 14 00 00 31 c0}  //weight: 1, accuracy: High
        $x_1_4 = "/etc/cron.hourly/gcc.sh" ascii //weight: 1
        $x_1_5 = "update-rc.d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Linux_Xorddos_AA_2147817653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Xorddos.AA"
        threat_id = "2147817653"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Xorddos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/etc/cron.hourly/gcc.sh" ascii //weight: 2
        $x_2_2 = "/etc/crontab && echo '*/3 * * * * root /etc/cron.hourly/gcc.sh' >> /etc/crontab" ascii //weight: 2
        $x_2_3 = "cp /lib/libudev.so /lib/libudev.so.6" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

