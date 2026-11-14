rule Ransom_Win32_Velcrina_A_2147982155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Velcrina.A"
        threat_id = "2147982155"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Velcrina"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {53 57 89 7d b8 c7 45 c0 52 00 41 00 c7 45 c4 42 00 00 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

