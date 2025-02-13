rule Trojan_Win32_Gupre_A_2147688931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gupre.A"
        threat_id = "2147688931"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gupre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 00 00 00 00 58 83 c0 1d b9 f7 02 00 00 80 38 a1 74 0d c0 08 02 80 30 a1 40 49 83 f9 00 75 f3 61}  //weight: 1, accuracy: High
        $x_1_2 = {67 00 75 00 70 00 64 00 61 00 74 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00 00 00 75 00 70 00 64 00 61 00 74 00 65 00 00 00 00 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

