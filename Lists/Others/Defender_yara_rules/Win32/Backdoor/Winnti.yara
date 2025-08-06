rule Backdoor_Win32_Winnti_MR_2147948636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Winnti.MR!MTB"
        threat_id = "2147948636"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Winnti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 0c 83 c0 28 8b 4d 18 8b 10 89 11 8b 50 04 89 51 04 8b 50 08 89 51 08 8b 40 0c 89 41 0c}  //weight: 10, accuracy: High
        $x_5_2 = "VEtWSU8tS1ZKTlQtTkRGV0gtVUFXSFYtWkZaUFI=" ascii //weight: 5
        $x_2_3 = "a.rooroad.com:53" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

