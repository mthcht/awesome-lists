rule Trojan_Win32_Regonid_A_2147655105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Regonid.A"
        threat_id = "2147655105"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Regonid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 65 67 69 73 74 72 61 74 69 6f 6e 49 44 ?? ?? 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d0 2b d1 03 55 14 83 fa 7e 76 03 83 c1 7e 8b 55 08 8a 14 10 8b 1e 2a d1 02 55 14 02 d0 88 14 18 40 3b c7 72 da}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

