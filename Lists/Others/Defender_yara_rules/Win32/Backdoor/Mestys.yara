rule Backdoor_Win32_Mestys_A_2147620635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mestys.A"
        threat_id = "2147620635"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mestys"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {6e 74 64 6c 6c 2e 64 6c 6c 00 4e 74 51 75 65 72 79 4f 62 6a 65 63 74 00 00 5c 00 42 00 61 00 73 00 65 00 4e 00 61 00 6d 00 65 00 64 00 4f 00 62 00 6a 00 65 00 63 00 74 00 73 00 5c 00 36 00 39 00 35 00 33 00 45 00 41 00 36 00 30 00 2d 00 38 00 44 00 35 00 46 00 2d 00 34 00 35 00 32 00 39 00 2d 00 38 00 37 00 31 00 30 00 2d 00 34 00 32 00 46 00 38 00 45 00 44 00 33 00 45 00 38 00 43 00 44 00 41 00}  //weight: 10, accuracy: High
        $x_10_2 = "Microsoft Corporation. All rights reserved." wide //weight: 10
        $x_1_3 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_4 = "NtQuerySystemInformation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

