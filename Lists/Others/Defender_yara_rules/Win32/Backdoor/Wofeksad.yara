rule Backdoor_Win32_Wofeksad_A_2147696378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Wofeksad.A!dha"
        threat_id = "2147696378"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Wofeksad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b1 07 b0 7a 88 4c 24 0e 88 4c 24 18 b1 66 b2 d4 88 4c 24 1f 88 4c 24 28 53 b1 a6 56}  //weight: 1, accuracy: High
        $x_1_2 = {00 42 3a 5c 00 41 3a 5c 00 77 69 6e 69 6e 65 74 2e 64 6c 6c 00 75 72 6c 6d 6f 6e 2e 64 6c 6c 00 00 25 64 2d 25 64 2d 25 64 20 25 64 3a 25 64 3a 25 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 5f 75 70 6c 6f 61 64 5f 00 00 00 00 70 3a 2f 2f 00 00 00 00 68 74 74 00 72 62 00 00 31 32 37 2e 30 2e 30 2e 31 00 00 00 3f 2a 2a 3f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

