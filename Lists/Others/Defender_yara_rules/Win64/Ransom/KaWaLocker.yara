rule Ransom_Win64_KaWaLocker_A_2147947000_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/KaWaLocker.A"
        threat_id = "2147947000"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "KaWaLocker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6b 00 69 00 6c 00 6c 00 5f 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 00 00 00 00 00 00 00 00 76 00 61 00 6c 00 75 00 65 00 00 00 00 00 00 00 6b 00 69 00 6c 00 6c 00 5f 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00}  //weight: 1, accuracy: High
        $x_1_2 = "KaWaLocker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

