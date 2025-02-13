rule Trojan_AndroidOS_Leech_A_2147829075_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Leech.A!xp"
        threat_id = "2147829075"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Leech"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/data/local/tmp/watchdog.pid" ascii //weight: 1
        $x_1_2 = "/system/bin/pm uninstall" ascii //weight: 1
        $x_1_3 = "get_command_interval" ascii //weight: 1
        $x_1_4 = "/system/usr/.hd_recovery" ascii //weight: 1
        $x_1_5 = "chmod 777 /system/app/%s.apk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

