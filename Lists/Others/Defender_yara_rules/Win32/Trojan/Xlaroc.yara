rule Trojan_Win32_Xlaroc_B_2147647447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Xlaroc.B"
        threat_id = "2147647447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Xlaroc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {84 c0 74 04 b3 01 eb 2b b2 01 a1}  //weight: 10, accuracy: High
        $x_10_2 = {e8 da d8 f9 ff 8b 45 f8 e8}  //weight: 10, accuracy: High
        $x_10_3 = {84 c0 74 0c 8b fb 8b c7 e8 90 71 fe ff 89 7e 44}  //weight: 10, accuracy: High
        $x_10_4 = {43 6f 72 61 6c 45 78 70 6c 6f 72 65 72 5f 32 30 30 34 32 31 2e 65 78 65 00}  //weight: 10, accuracy: High
        $x_10_5 = {46 75 6e 73 68 69 6f 6e 49 6e 73 74 61 6c 6c 2e 65 78 65 00}  //weight: 10, accuracy: High
        $x_1_6 = {7b 46 43 39 36 46 33 34 35 2d 44 32 44 46 2d 34 43 43 41 2d 39 42 38 38 2d 43 43 44 43 30 34 37 46 46 33 31 37 7d 00}  //weight: 1, accuracy: High
        $x_1_7 = {63 3a 5c 37 46 41 35 35 34 44 41 2e 6c 6f 67 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

