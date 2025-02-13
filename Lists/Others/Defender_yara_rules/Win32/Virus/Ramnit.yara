rule Virus_Win32_Ramnit_2147642440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Ramnit!remnants"
        threat_id = "2147642440"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Ramnit"
        severity = "Critical"
        info = "remnants: remnants of a virus"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 33 d2 b9 1d f3 01 00 f7 f1 8b c8 b8 a7 41 00 00 f7 e2 8b d1 8b c8 b8 14 0b 00 00 f7 e2 2b c8 33 d2 8b c1 8b d9 f7 75 0c}  //weight: 1, accuracy: High
        $x_1_2 = {81 ef 00 00 01 00 81 ff 00 00 00 70 73 ?? bf 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8b f8 c6 07 2d 47 6a 04 57 ff b5 ?? ?? ff ff 8d 83 64 a7 01 20 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Ramnit_EC_2147908291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Ramnit.EC!MTB"
        threat_id = "2147908291"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Ramnit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_8_1 = {32 1f 88 1f 47 4a e2 e6 68 ff 00 00 00}  //weight: 8, accuracy: High
        $x_1_2 = "KyUffThOkYwRRtgPP" ascii //weight: 1
        $x_1_3 = "Srv.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

