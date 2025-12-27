rule Trojan_Win32_BrightEgg_A_2147957183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BrightEgg.A!dha"
        threat_id = "2147957183"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BrightEgg"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 01 89 45 ?? 83 7d ?? 04 7d 1e 8b 45 08 03 45 ?? 0f b6 08 8b 55 0c 03 55 ?? 0f b6 02 33 c8 8b 55 10 03 55 ?? 88 0a eb d3 03 00 8b 45}  //weight: 1, accuracy: Low
        $x_1_2 = {8b f4 68 98 3a 00 00 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {8b f4 6a 40 68 00 10 00 00 68 ?? 1c 00 00 6a 00 ff 15 ?? ?? ?? ?? 3b f4 e8 ?? ?? ?? ?? 89 45 ?? 68 ?? 1c 00 00 8b 45 ?? 50 8b 4d ?? 51 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_BrightEgg_B_2147957184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BrightEgg.B!dha"
        threat_id = "2147957184"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BrightEgg"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6b 65 72 6e c7 45 ?? 65 6c 33 32 c7 45 ?? 2e 64 6c 6c c7 45 ?? 56 69 72 74 c7 45 ?? 75 61 6c 41 c7 45 ?? 6c 6c 6f 63 ff 15 03 00 c7 45}  //weight: 5, accuracy: Low
        $x_1_2 = {6a 00 57 6a 00 6a 00 ff 15 ?? ?? ?? ?? 50 0b 00 68 ?? (39|(3a|3b)) 00 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

