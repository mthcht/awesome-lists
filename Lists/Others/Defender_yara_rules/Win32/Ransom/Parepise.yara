rule Ransom_Win32_Parepise_A_2147749442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Parepise.A"
        threat_id = "2147749442"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Parepise"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 00 68 00 6f 00 72 00 73 00 65 00 64 00 65 00 61 00 6c 00 00 00 00 00 25 00 73 00 25 00 73 00 00 00 00 00 5f 00 75 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 69 00 6e 00 67 00 5f 00 2e 00 70 00 6e 00 67 00 00 00 00 00 25 00 73 00 5c 00 2a 00 00 00 00 00 25 00 73 00 5c 00 25 00 73 00 00 00 2e 00 00 00 2e 00 2e 00 00 00 00 00 23 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

