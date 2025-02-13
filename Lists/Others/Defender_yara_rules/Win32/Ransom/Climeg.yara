rule Ransom_Win32_Climeg_A_2147717948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Climeg.A"
        threat_id = "2147717948"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Climeg"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 61 6e 73 6f 6d 5c 63 73 5c 72 61 6e 73 6f 6d 5c 72 61 6e 73 6f 6d 5c 6f 62 6a 5c 44 65 62 75 67 5c 72 61 6e 73 6f 6d 2e 70 64 62 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

