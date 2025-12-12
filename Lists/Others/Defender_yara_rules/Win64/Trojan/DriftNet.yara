rule Trojan_Win64_DriftNet_A_2147959336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DriftNet.A"
        threat_id = "2147959336"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DriftNet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 3a 5c 70 72 6f 6a 65 63 74 73 5c 6d 6f 64 75 6c 65 73 5c 73 68 65 6c 6c 63 6f 64 65 5c 73 68 65 6c 6c 63 6f 64 65 5f 6d 6f 64 75 6c 65 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 73 68 65 6c 6c 63 6f 64 65 5f 6d 6f 64 75 6c 65 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_2 = {61 64 73 66 38 31 69 73 61 6b 61 61 6b 30 78 00}  //weight: 1, accuracy: High
        $x_1_3 = {41 b9 04 00 00 00 41 b8 00 30 00 00 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

