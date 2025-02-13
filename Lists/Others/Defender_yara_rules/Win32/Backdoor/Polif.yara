rule Backdoor_Win32_Polif_A_2147668399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Polif.A"
        threat_id = "2147668399"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Polif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 e0 47 c1 e0 51 c1 e0 55}  //weight: 1, accuracy: High
        $x_1_2 = {bf b0 15 00 00 3b cf 73 02 8b f9 2b cf 0f b6 16}  //weight: 1, accuracy: High
        $x_1_3 = {c6 44 24 02 4d c6 44 24 03 5a c7 44 24 04 90 00 03 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

