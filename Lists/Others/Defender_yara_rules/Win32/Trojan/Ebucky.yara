rule Trojan_Win32_Ebucky_A_2147735591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ebucky.A"
        threat_id = "2147735591"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ebucky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b1 7e 30 0d ?? ?? ?? ?? 30 0d ?? ?? ?? ?? 30 0d ?? ?? ?? ?? 30 0d ?? ?? ?? ?? 30 0d ?? ?? ?? ?? 30 0d ?? ?? ?? ?? 30 0d ?? ?? ?? ?? 33 c0 eb 07 8d a4 24 00 00 00 00 30 88 ?? ?? ?? ?? 40 83 f8 0f}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 44 3e 04 3a c2 74 17 84 c0 74 13 3c 23 74 0f 8a da 80 f3 23 3a c3 74 06 32 c2 88 44 3e 04 47 3b f9 7c dc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

