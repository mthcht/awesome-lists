rule Backdoor_AndroidOS_KungFu_A_2147822851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/KungFu.A!xp"
        threat_id = "2147822851"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "KungFu"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 03 d0 05 23 5b 42 08 93 d3 e7 30 1c 29 1c ff f7 09 ff 08}  //weight: 1, accuracy: Low
        $x_1_2 = "/system/etc/.rild_cfg" ascii //weight: 1
        $x_1_3 = "/system/bin/pm install -r" ascii //weight: 1
        $x_1_4 = "oknolock" ascii //weight: 1
        $x_1_5 = "/system/bin/pm uninstall" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

