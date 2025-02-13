rule TrojanDropper_Win32_Livuto_2147604764_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Livuto"
        threat_id = "2147604764"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Livuto"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 13 99 59 f7 f9 8b 45 ?? 80 c2 61 88 14 06 46 83 fe 0b 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {80 c9 ff 2a 08 47 81 ff ?? ?? ?? ?? 88 08 72 ea}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Livuto_A_2147612730_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Livuto.gen!A"
        threat_id = "2147612730"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Livuto"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 10 72 e4 33 c9 0f b6 91 ?? ?? ?? ?? 8d 81 ?? ?? ?? ?? 41 8a 94 15 ?? ?? ?? ff 83 f9}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 07 33 ff 99 59 f7 f9 8b f2 83 c6 04 85 f6 7e 0d e8 ?? ?? ?? ?? 88 04 1f 47 3b fe 7c f3}  //weight: 1, accuracy: Low
        $x_2_3 = {ff 51 1c 85 c0 75 5d 8b 45 fc 50 8b 08 ff 51 14 8b 45 fc 8d 55 ?? 52 8d 55 ?? 8b 08 52 6a 01 50 ff 51 0c 85 c0 75 3d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

