rule Backdoor_Win32_Zusy_ARR_2147970580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zusy.ARR!MTB"
        threat_id = "2147970580"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_8_1 = {44 8b c0 b8 67 66 66 66 41 f7 e8 c1 fa 02 8b ca c1 e9 1f 03 d1 8d 0c 92 03 c9 44 2b c1 41 83 f8 03}  //weight: 8, accuracy: High
        $x_12_2 = {8b d8 b8 89 88 88 88 f7 eb 03 d3 c1 fa 09 8b c2 c1 e8 1f 03 d0 69 c2 c0 03 00 00 2b d8 83 c3 40}  //weight: 12, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

