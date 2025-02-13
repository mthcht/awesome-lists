rule Backdoor_Win32_Wingbird_A_2147723539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Wingbird.gen.A!dha"
        threat_id = "2147723539"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Wingbird"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c5 89 45 fc 8b 4d 08 53 56 57 33 c0 0f 84}  //weight: 1, accuracy: High
        $x_3_2 = {8d 64 24 0c 33 c9 81 e9 ?? ?? ?? ?? 51 81 f1 ?? ?? ?? ?? 51 81 c1 ?? ?? ?? ?? 51 81 e9 ?? ?? ?? ?? 51 81 f1 ?? ?? ?? ?? 51 54 ff b5 ?? ?? ff ff ff 15}  //weight: 3, accuracy: Low
        $x_1_3 = {33 c9 81 e9 ?? ?? ?? ?? 51 81 f1 ?? ?? ?? ?? 51 54 ff b5 ?? ?? ff ff ff 15}  //weight: 1, accuracy: Low
        $x_2_4 = {03 49 3c 0f ?? ?? ?? 00 00 0f b7 51 14 83 c2 14}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

