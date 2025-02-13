rule Trojan_Win32_Netnam_B_2147696126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Netnam.B"
        threat_id = "2147696126"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Netnam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6c 69 62 65 72 61 74 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {54 31 59 39 34 33 6a 49 68 6b 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b 81 0c 01 00 00 66 8b 4c 24 04 66 89 08 c2 04 00}  //weight: 1, accuracy: High
        $x_1_4 = {f7 b1 04 01 00 00 8a 04 3e 8a 14 0a 3a c2 74 09 84 c0 74 05 32 c2 88 04 (3e)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

