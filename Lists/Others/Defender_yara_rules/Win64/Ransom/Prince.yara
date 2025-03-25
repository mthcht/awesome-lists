rule Ransom_Win64_Prince_E_2147936877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Prince.E"
        threat_id = "2147936877"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Prince"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 75 6e 63 31 00 6c 6f 67 2e 50 72 69 6e 74 6c 6e 00 6c 6f 67 2e 69 6e 69 74 00 6c 6f 67 2e 4e 65 77 00 50 72 69 6e 63 65 2d 52 61 6e 73 6f 6d 77 61 72 65 2f 65 6e 63 72 79 70 74 69 6f 6e 2e 69 6e 69 74 2e 30 00 50 72 69 6e 63 65 2d 52 61 6e 73 6f 6d 77 61 72 65 2f 65 6e 63 72 79 70 74 69 6f 6e 2e 45 6e 63 72 79 70 74 46 69 6c 65 ?? 50 72 69 6e 63 65 2d 52 61 6e 73 6f 6d 77 61 72 65 2f 65 6e 63 72 79 70 74 69 6f 6e 2e 67 65 6e 65 72 61 74 65 4b 65 79 00 50 72 69 6e 63 65 2d 52 61 6e 73 6f 6d 77 61 72 65 2f 65 6e 63 72 79 70 74 69 6f 6e 2e 67 65 6e 65 72 61 74 65 4e 6f 6e 63 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

