rule Trojan_Win32_Blocix_A_2147650887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Blocix.A"
        threat_id = "2147650887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Blocix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 69 6e 67 20 31 2e 31 2e 31 2e 31 20 2d 77 20 35 30 30 30 20 3e 6e 75 6c 0d 0a 69 66 20 65 78 69 73 74 20 22 25 73 22}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 0c 85 c0 75 0c 6a 3f 68 ?? ?? ?? ?? e9 ?? ?? 00 00 83 f8 01 75 09 6a 3f 68 ?? ?? ?? ?? eb ?? 83 f8 02 75 ?? 6a 3f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

