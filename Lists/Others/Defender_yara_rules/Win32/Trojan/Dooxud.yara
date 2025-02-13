rule Trojan_Win32_Dooxud_A_2147644889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dooxud.A"
        threat_id = "2147644889"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dooxud"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 f9 80 c2 61 88 54 34 04 46 83 fe 05 7c e6}  //weight: 1, accuracy: High
        $x_1_2 = {6a 04 68 00 30 00 00 8b f0 51 6a 00 56 ff d3 8b 54 24 14 8b f8 8b 44 24 18 6a 00 52 50 57 56}  //weight: 1, accuracy: High
        $x_1_3 = {45 52 52 00 32 4b 38 00 57 4e 37}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

