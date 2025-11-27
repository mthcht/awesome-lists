rule Trojan_Win64_BurnBook_SX_2147958427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BurnBook.SX!MTB"
        threat_id = "2147958427"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BurnBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {43 30 0c 3e 41 ff c6 0f b6 ?? 01 fe ?? 88 ?? 01 [0-2] 40 75}  //weight: 20, accuracy: Low
        $x_20_2 = {43 30 0c 3e 41 ff c6 fe [0-2] 0f b6 ?? 01 0f b6 ?? 3c 40 75}  //weight: 20, accuracy: Low
        $x_10_3 = {33 d2 48 8d 8d ?? ?? ?? ?? 41 b8 04 01 00 00 e8 ?? ?? ?? ?? 48 8d 0d ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8b d8 48 85 c0 0f 84 ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 4c [0-3] 8d 45 ?? 48 89 44 24 20 ba 04 01 00 00}  //weight: 10, accuracy: Low
        $x_1_4 = "APPDATA" ascii //weight: 1
        $x_1_5 = "sumatrapdf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

