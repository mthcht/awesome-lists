rule Trojan_Win32_Niblenyo_B_2147610063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Niblenyo.gen!B"
        threat_id = "2147610063"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Niblenyo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 77 6e 44 4c 4c 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {8a c3 83 f8 05 (75 7f|0f 85 84 00) 8b c3 e8 ?? ?? ff ff 84 c0 75 0e 68 ?? ?? 40 00 e8 ?? ?? ff ff 8b f0 eb 0c 68 ?? ?? 40 00 e8 ?? ?? ff ff 8b f0 6a 02 56 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {83 7d fc 00 0f 86 ?? ?? 00 00 83 3d ?? ?? 40 00 01 1b c0 40 84 c0 0f 85 [0-14] 8b 45 fc e8 ?? ?? ff ff 8b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

