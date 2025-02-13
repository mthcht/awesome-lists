rule Worm_Win32_Makeup_A_2147607921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Makeup.gen!A"
        threat_id = "2147607921"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Makeup"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "_Oscar_StatusNotify" ascii //weight: 1
        $x_1_2 = "__oxFrame.class__" ascii //weight: 1
        $x_1_3 = "gdkWindowToplevel" ascii //weight: 1
        $x_1_4 = "TskMultiChatForm.UnicodeClass" ascii //weight: 1
        $x_1_5 = "IMWindowClass" ascii //weight: 1
        $x_5_6 = {6a 00 6a 00 6a 00 6a 11 ff 15 ?? ?? ?? ?? 6a 00 6a 00 6a 00 6a 61 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 6a 00 6a 00 6a 00 6a 2e ff 15}  //weight: 5, accuracy: Low
        $x_10_7 = {6a 00 6a 02 6a 00 0f b7 85 ?? ?? ff ff 8a 84 05 ?? ?? ff ff 50 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 6a 64 ff 15 ?? ?? ?? ?? eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Makeup_B_2147607922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Makeup.gen!B"
        threat_id = "2147607922"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Makeup"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "shell\\infected\\command=%s" ascii //weight: 1
        $x_1_2 = {00 6f 70 65 6e 00}  //weight: 1, accuracy: High
        $x_10_3 = {83 f8 02 75 34 89 5c 24 08 ba 05 00 00 00 b8 ?? ?? ?? ?? 89 54 24 14 31 ff be ?? ?? ?? ?? 89 7c 24 10 89 74 24 0c 89 44 24 04 c7 04 24 00 00 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

