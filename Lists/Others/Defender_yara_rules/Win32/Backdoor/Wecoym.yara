rule Backdoor_Win32_Wecoym_A_2147694930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Wecoym.A"
        threat_id = "2147694930"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Wecoym"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 8b fa 88 5c 24 14 8a cb 33 d2 89 4c 24 18 8b f5 42 8a 06 3c 2e 74 28 3c 3e 74 24 3c 36 74 20 3c 26 74 1c 3c 64 74 18}  //weight: 1, accuracy: High
        $x_1_2 = {85 c0 75 0a 39 47 08 74 05 ff 77 08 eb 2b 53 68}  //weight: 1, accuracy: High
        $x_1_3 = "_5pecjkjklt_" ascii //weight: 1
        $x_1_4 = {77 65 79 2e 63 6f 6d 00 7e}  //weight: 1, accuracy: High
        $x_1_5 = {50 52 49 56 4d 53 47 00 32 4b 00 00 58 50 00 00 32 4b 33 00 56 53 00 00 32 4b 38 00 57 37}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

