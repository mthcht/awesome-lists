rule Ransom_Win32_Sobnot_A_2147723893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sobnot.A"
        threat_id = "2147723893"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sobnot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {75 00 00 00 6d 00 69 00 64 00 00 00 77 00 6d 00 61 00 00 00 66 00 6c 00 76 00 00 00 33 00 67 00 32 00 00 00 6d 00 6b 00 76 00 00 00 33 00 67 00 70 00 00 00 6d 00 70 00 34 00 00 00 6d 00 6f 00 76 00 00 00 61 00 76 00 69 00 00 00 61 00 73 00 66 00 00 00 6d 00 70 00 65 00 67 00 00 00 00 00 76 00 6f 00 62 00 00 00 6d 00 70 00 67 00 00 00 77 00 6d 00 76 00 00 00 66 00 6c 00 61 00 00 00 73 00 77 00 66 00 00 00 77 00 61 00 76 00 00 00 6d 00 70 00 33 00 00 00 5c 00 00 00 2e 00 00 00 5c 00 00 00 2e 00 65 00 78 00 65 00 00 00 00 00 2e 00 00 00 22 00 00 00 2e 00 00 00 2e 00 00 00 2e 00 00 00 5c 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 5c 00 72 00 6f 00 61 00 6d 00 69 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

