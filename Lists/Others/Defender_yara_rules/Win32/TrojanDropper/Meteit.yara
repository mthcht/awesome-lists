rule TrojanDropper_Win32_Meteit_A_2147646659_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Meteit.A"
        threat_id = "2147646659"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Meteit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Internet Explorer\\SIGNUP\\*.ins" ascii //weight: 1
        $x_1_2 = {5c 6d 73 61 64 6f [0-4] 2e}  //weight: 1, accuracy: Low
        $x_1_3 = {83 c4 14 8d 85 ?? ?? ff ff 68 ?? ?? ?? ?? 50 8d 45 ?? 50 ff 15 ?? ?? ?? ?? 8d 85 ?? ?? ff ff 50 8d 85 ?? ?? ff ff 50 ff 15 ?? ?? ?? ?? 83 f8 ff 74 09 8d 85 ?? ?? ff ff 50 ff d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Meteit_D_2147648909_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Meteit.D"
        threat_id = "2147648909"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Meteit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 04 33 c0 8a 0a 84 c9 74 ?? 6b c0 1f 0f be c9 03 c1 42}  //weight: 1, accuracy: Low
        $x_2_2 = {8b 48 04 ff 45 08 83 e9 08 42 d1 e9 42 39 4d 08 72}  //weight: 2, accuracy: High
        $x_1_3 = {8b 46 08 8b 4d 08 8b 04 88 83 f8 ff 74 ?? 50 ff 57 08}  //weight: 1, accuracy: Low
        $x_1_4 = {2b c8 b8 ab aa aa 2a f7 e9 d1 fa 8b c2 c1 e8 1f 03 d0 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

