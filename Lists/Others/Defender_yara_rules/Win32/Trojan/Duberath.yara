rule Trojan_Win32_Duberath_A_2147632436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Duberath.A"
        threat_id = "2147632436"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Duberath"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {50 68 7e 66 04 80}  //weight: 4, accuracy: High
        $x_1_2 = "AdobeUpdate" ascii //weight: 1
        $x_1_3 = {64 75 62 6f 73 65 6c 61 77 2e 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_4 = {44 65 66 57 61 74 63 68 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_2_5 = {45 00 4e 00 45 00 4d 00 49 00 45 00 53 00 5f 00 52 00 00 00}  //weight: 2, accuracy: High
        $x_2_6 = {50 00 52 00 4f 00 58 00 49 00 45 00 53 00 5f 00 52 00 00 00}  //weight: 2, accuracy: High
        $x_2_7 = {44 00 4f 00 57 00 4e 00 4c 00 4f 00 41 00 44 00 5f 00 52 00 00 00}  //weight: 2, accuracy: High
        $x_1_8 = {2e 00 61 00 74 00 68 00 2e 00 63 00 78 00 3a 00 38 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

