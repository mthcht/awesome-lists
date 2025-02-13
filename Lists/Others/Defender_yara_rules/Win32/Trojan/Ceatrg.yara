rule Trojan_Win32_Ceatrg_A_2147664434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ceatrg.A"
        threat_id = "2147664434"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ceatrg"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 46 7c 00 ff ff ff ff 06 00 00 00 46 6c 6f 6f 64 5b 00}  //weight: 1, accuracy: High
        $x_1_2 = {6a 00 68 01 20 00 00 56 8b 43 04 50 e8 ?? ?? ?? ?? 85 c0 7e 03 40 75 ?? 8b 43 04 50 e8 ?? ?? ?? ?? 68 88 13 00 00 e8 ?? ?? ?? ?? e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

