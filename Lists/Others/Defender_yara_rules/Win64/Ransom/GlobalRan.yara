rule Ransom_Win64_GlobalRan_A_2147943806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/GlobalRan.A"
        threat_id = "2147943806"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "GlobalRan"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 6d 61 69 6e 2e 70 72 6f 67 72 65 73 73 52 65 70 6f 72 74 65 72 00 6d 61 69 6e 2e 70 72 6f 67 72 65 73 73 52 65 70 6f 72 74 65 72 2e 64 65 66 65 72 77 72 61 70 31 00 6d 61 69 6e 2e 6c 6f 61 64 50 75 62 6c 69 63 4b 65 79 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 6d 61 69 6e 2e 64 72 6f 70 4e 6f 74 65 00 6d 61 69 6e 2e 65 6e 63 72 79 70 74 44 69 72 65 63 74 6f 72 79 ?? 6d 61 69 6e 2e 65 6e 63 72 79 70 74 44 69 72 65 63 74 6f 72 79 2e 66 75 6e 63 32 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

