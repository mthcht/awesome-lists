rule TrojanDownloader_Win32_Rechide_A_2147647477_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rechide.A"
        threat_id = "2147647477"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rechide"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 55 49 6d 67 72 00 00 20 64 62 67 65 6e 75 6d}  //weight: 1, accuracy: High
        $x_1_2 = {69 6e 73 74 61 6c 6c 00 64 62 67 65 6e 75 6d}  //weight: 1, accuracy: High
        $x_1_3 = {63 3a 5c 72 65 63 79 63 6c 65 72 5c [0-32] 63 3a 5c 72 65 63 79 63 6c 65 72 5c [0-32] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = {56 69 63 74 69 6d 3a 20 25 73 2d 25 78 00 00 00 46 69 6c 65 3a 20}  //weight: 1, accuracy: High
        $x_1_5 = "U1R1L1D1o1w1n1l1o1a1d1T1o1F1i1l1e1A1" ascii //weight: 1
        $x_1_6 = "http://%s/%s?h=%s-%x&r=%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

