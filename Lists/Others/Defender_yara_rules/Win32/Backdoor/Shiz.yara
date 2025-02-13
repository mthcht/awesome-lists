rule Backdoor_Win32_Shiz_DF_2147821123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Shiz.DF!MTB"
        threat_id = "2147821123"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Shiz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4c 24 08 8d 14 0e 33 c9 8a cc 32 0a 88 0a 66 0f b6 c9 03 c8 b8 bf 58 00 00 69 c9 93 31 00 00 2b c1 46 3b 74 24 0c 72 d7}  //weight: 1, accuracy: High
        $x_1_2 = {8b 44 24 0c 33 db 8a de 8d 0c 06 8a 04 06 32 d8 66 0f b6 c0 03 c2 ba bf 58 00 00 69 c0 93 31 00 00 2b d0 46 3b 74 24 10 88 19 72 d4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

