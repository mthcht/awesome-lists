rule Trojan_WinNT_Noviq_A_2147632575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Noviq.A"
        threat_id = "2147632575"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Noviq"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 64 00 65 00 76 00 57 00 72 00 69 00 74 00 65 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 00 52 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 5c 00 4d 00 61 00 63 00 68 00 69 00 6e 00 65 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5c 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {6b c0 28 03 c6 eb ?? ff 74 24 04 8b ce e8 ?? ff ff ff 8b c8 85 c9 74 12 8b 46 3c 48 f7 d0 23 41 14 2b 41 0c 03 44 24 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

