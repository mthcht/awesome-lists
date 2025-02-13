rule Trojan_Win32_Zespam_A_2147681109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zespam.A"
        threat_id = "2147681109"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zespam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 61 64 64 5f 61 74 74 61 63 68 5f 75 72 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {66 8b 11 66 89 55 ?? 0f b7 45 ?? 50 e8 ?? ?? ?? ?? 83 c4 04 0f b7 c8 33 4d ?? 81 e1 ff 00 00 00 8b 55 ?? c1 ea 08 33 14 8d ?? ?? ?? ?? 89 55 ?? 8b 45 ?? 83 c0 02 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

