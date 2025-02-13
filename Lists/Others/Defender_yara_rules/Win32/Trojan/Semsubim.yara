rule Trojan_Win32_Semsubim_A_2147696881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Semsubim.A"
        threat_id = "2147696881"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Semsubim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 6a 05 56 c6 44 24 25 c0 c6 44 24 26 c2 c6 44 24 27 0c ff d3 8b 4c 24 14 32 c0 89 0e 88 46 04}  //weight: 1, accuracy: High
        $x_1_2 = {c6 44 24 08 b8 50 6a 40 6a 08 56 c6 44 24 19 01 c6 44 24 1d c2 c6 44 24 1e 04 ff 15 ?? ?? ?? ?? 8b 4c 24 08 8b 54 24 0c 89 0e 89 56 04}  //weight: 1, accuracy: Low
        $x_1_3 = {c1 fe 02 ff 15 ?? ?? ?? ?? 33 d2 8b 4c 24 ?? f7 f6 8b 14 91 52 8b 54 24 ?? ?? 68 02 05 00 00 8b 42 20 50 ff d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

