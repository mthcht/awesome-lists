rule Backdoor_Win32_Wonknuwi_A_2147624519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Wonknuwi.A"
        threat_id = "2147624519"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Wonknuwi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 1e 8b fb 8a 82 ?? ?? ?? ?? 32 c8 33 c0 88 0c 1e 83 c9 ff 46 f2 ae f7 d1 49 3b f1 72 d7}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 8c 24 60 01 00 00 68 b4 00 00 00 51 52 e8 ?? ?? ?? ?? 8b e8 3b eb 74 05 83 fd ff 75 5a}  //weight: 1, accuracy: Low
        $x_1_3 = {55 6e 6b 6e 6f 77 00 00 57 69 6e 64 6f 77 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

