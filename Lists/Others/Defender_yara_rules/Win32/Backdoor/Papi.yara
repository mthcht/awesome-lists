rule Backdoor_Win32_Papi_D_2147619816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Papi.D"
        threat_id = "2147619816"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Papi"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 41 50 41 50 49 33 32 [0-5] 43 72 65 61 74 65 53 65 72 76 69 63 65 20 66 61 69 6c [0-5] 4f 70 65 6e 53 65 72 76 69 63 65 20 66 61 69 6c}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 17 80 ea 41 8a 4f 01 80 e9 41 c1 e1 04 02 d1 88 10 80 ea ?? 80 f2 ?? 80 c2 ?? 88 10 40 83 c7 02 4e 75 dc}  //weight: 1, accuracy: Low
        $x_1_3 = {80 38 2a 74 22 46 40 4a 75 f6 eb 1b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

