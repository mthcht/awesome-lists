rule Backdoor_Win32_Wnpms_A_2147605805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Wnpms.A"
        threat_id = "2147605805"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Wnpms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6d 73 64 6f 77 6e 6c 6f 61 64 65 72 00 20 00 43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 77 6e 70 6d 73 2e 65 78 65}  //weight: 2, accuracy: High
        $x_1_2 = "_win32__wnpms_sm__" ascii //weight: 1
        $x_1_3 = "__win32__wnpms_sdm__" ascii //weight: 1
        $x_2_4 = {6d 79 20 70 6f 72 74 20 5b 25 69 5d 0a 00 64 65 70 2e 6d 76 6c 30 61 6e 37 2e 63 6f 6d 00 61 75 74 68 6f 72 69 7a 65 64 20 49 50}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

