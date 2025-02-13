rule Backdoor_Win32_Rusdonet_A_2147694020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rusdonet.A"
        threat_id = "2147694020"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rusdonet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 02 8b 4d fc 33 d2 8a 94 0d fc fe ff ff 33 c2 8b 4d 10 03 8d ec fd ff ff 88 01 e9}  //weight: 1, accuracy: High
        $x_1_2 = {83 f8 63 75 42 0f be ?? ?? ?? ?? ?? 83 f9 6f 75 36 0f be ?? ?? ?? ?? ?? 83 fa 6e}  //weight: 1, accuracy: Low
        $x_1_3 = {4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 2f 00 34 00 2e 00 30 00 00 00 72 00 65 00 71 00 75 00 65 00 73 00 74 00 00 00 68 00 74 00 6d 00 6c 00 00 00 00 00 64 00 61 00 74 00 61 00 20 00 69 00 73 00 20 00 25 00 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 00 00 50 00 72 00 6f 00 78 00 79 00 45 00 6e 00 61 00 62 00 6c 00 65 00 00 00 73 00 79 00 73 00 69 00 6e 00 66 00 6f 00}  //weight: 1, accuracy: High
        $x_1_5 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 37 00 00 00 75 00 6e 00 6b 00 6f 00 77 00 6e 00 00 00 00 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

