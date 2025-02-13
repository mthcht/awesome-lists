rule Backdoor_MacOS_X_Olyx_B_2147655207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS_X/Olyx.B"
        threat_id = "2147655207"
        type = "Backdoor"
        platform = "MacOS_X: "
        family = "Olyx"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "<key>RunAtLoad</key>" ascii //weight: 1
        $x_1_2 = "/Library/LaunchAgents/" ascii //weight: 1
        $x_3_3 = "/Library/Audio/Plug-Ins/AudioServer" ascii //weight: 3
        $x_3_4 = "dns.assyra.com" ascii //weight: 3
        $x_3_5 = {30 04 0a 48 ff c2 48 83 fa 10 75 ec 0f b6 01 c1 e0 08}  //weight: 3, accuracy: High
        $x_3_6 = {0f b6 82 14 02 00 00 32 01 88 82 14 02 00 00 0f b6 82 54 02 00 00 32 01 88 82 54 02 00 00 42 41 39 f1}  //weight: 3, accuracy: High
        $x_2_7 = {ba 00 00 00 00 83 f8 01 75 [0-6] 00 00 c7 00 fa ff ff ff ba 01 00 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

