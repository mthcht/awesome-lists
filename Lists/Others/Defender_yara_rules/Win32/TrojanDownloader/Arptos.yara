rule TrojanDownloader_Win32_Arptos_A_2147640162_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Arptos.A"
        threat_id = "2147640162"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Arptos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s?mac=%s&ver=%s" ascii //weight: 1
        $x_2_2 = {8a 0e 8a 18 2a d9 88 18 8a cb 8a 1e 32 d9 46 88 18 40 4f}  //weight: 2, accuracy: High
        $x_1_3 = {b1 6f b3 6e b0 6c b2 64}  //weight: 1, accuracy: High
        $x_1_4 = {c6 45 d1 72 c6 45 d2 69 c6 45 d3 6e c6 45 d4 69 c6 45 d5 74}  //weight: 1, accuracy: High
        $x_1_5 = {69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00 49 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 41 00 63 00 74 00 69 00 76 00 65 00 78 00 2e 00 45 00 58 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

