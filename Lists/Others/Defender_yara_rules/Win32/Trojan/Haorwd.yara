rule Trojan_Win32_Haorwd_B_2147731744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Haorwd.B"
        threat_id = "2147731744"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Haorwd"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a d0 80 e2 f0 02 d2 02 d2 08 17 8a d0 80 e2 fc c0 e2 04 08 16 c0 e0 06 08 01 c3}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 14 06 0f b6 4c 06 ?? 88 55 ?? 0f b6 54 06 ?? 8a 44 06 ?? 88 4d ?? 8d 4d ?? 8d 75 ?? 8d 7d ?? 88 55 ?? e8 ?? ?? ?? ?? 0f b6 4d ?? 8b 45 ?? 0f b6 55 ?? 88 0c 03 0f b6 4d ?? 43 88 14 03 43 88 0c 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

