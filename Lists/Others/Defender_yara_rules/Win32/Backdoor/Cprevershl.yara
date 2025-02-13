rule Backdoor_Win32_Cprevershl_B_2147779292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Cprevershl.B!MTB"
        threat_id = "2147779292"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Cprevershl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 6d 64 20 2f 63 20 63 6f 70 79 20 [0-32] 2e 65 78 65 20}  //weight: 1, accuracy: Low
        $x_1_2 = {63 6d 64 20 2f 63 20 52 45 47 20 41 44 44 20 48 4b 43 55 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 20 2f 56 20 22 [0-16] 22 20 2f 74 20 52 45 47 5f 53 5a 20 2f 46 20 2f 44}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 45 d4 63 6d 64 2e c7 45 d8 65 78 65 00 c7 44 24 08 44 00 00 00 c7 44 24 04 00 00 00 00 8d 85 ?? ?? ?? ?? 89 04 24 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

