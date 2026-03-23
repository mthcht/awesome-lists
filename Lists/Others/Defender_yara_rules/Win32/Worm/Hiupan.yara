rule Worm_Win32_Hiupan_2147965329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Hiupan"
        threat_id = "2147965329"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Hiupan"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 40 68 ?? ?? ?? ?? 68 00 30 00 10 ff 15 ?? ?? ?? ?? b8 00 30 00 10 ff d0 ff 15 ?? ?? ?? ?? 50 6a 01 68 01 00 10 00 ff 15 ?? ?? ?? ?? 6a 00 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 00 00 eb e5 8b 45 ?? 8b 8d ?? ?? ?? ?? 89 48 18 8b 45 ?? 8b 4d ?? 89 48 1c 8b 45 ?? 8b 8d ?? ?? ?? ?? 89 48 20 8b 45 ?? 8b 8d ?? ?? ?? ?? 89 08 8b 45 ?? 89 45 fc c6 85 ?? ?? ?? ?? 47 c6 85 ?? ?? ?? ?? 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

