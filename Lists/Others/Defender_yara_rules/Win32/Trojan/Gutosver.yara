rule Trojan_Win32_Gutosver_A_2147678798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gutosver.A"
        threat_id = "2147678798"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gutosver"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e aa c6 44 24 ?? 63 c6 44 24 ?? 6f c7 44 24 20 01 00 00 00 c6 44 24 ?? 6d 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {30 40 00 6a 02 68 ?? ?? ?? ?? ff (d6|d7) 8b ce e8 ?? ?? 00 00 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 54 24 28 8b 15 ?? ?? ?? ?? 89 54 24 2c 8b 15 ?? ?? ?? ?? 89 54 24 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

