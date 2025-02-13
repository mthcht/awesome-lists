rule Trojan_Win32_Padodor_GPB_2147903347_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Padodor.GPB!MTB"
        threat_id = "2147903347"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Padodor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {4d 5a 9b dd ff 7e 13 29 fe ab e5 60 00 d8 35 73 29 68 09 36 66 35 cf 7e f3 0d 7e 73 e5 7e 7e 90 8f 36 47 36 46 36 36 d7 8b 8b df 5e c3 7e 8b e5}  //weight: 5, accuracy: High
        $x_5_2 = {4d 5a e1 3d 08 ea f4 3f 2c 38 75 f4 98 2c 3d f4 74 4d 3d 75 3f 9d 3c 75 5d 1f b3 e6 90 3f 6e 75 3d 6e aa f4 3d 4d d7 75 38 75 4c f4 1f 75 75 3f}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Padodor_JPAA_2147906484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Padodor.JPAA!MTB"
        threat_id = "2147906484"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Padodor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 d8 01 d8 89 c3 81 eb e4 34 00 00 81 eb 3f 7a 00 00 89 d8 29 d8 89 c3 f7 e3 89 85 ?? ?? ?? ?? 89 c3 81 f3 1b 6a 00 00 89 d8 f7 e3 89 85 ?? ?? ?? ?? 89 c3 f7 e3 89 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Padodor_A_2147922415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Padodor.A!MTB"
        threat_id = "2147922415"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Padodor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {21 6b 86 ed a3 13 ea 1b 4b e2 a9 e3 21 6b 86 ee a3 07 ea 1b 4b e2 a9 e7 21 6b 86 ef a3 0b ea 1b 4b e2 a9 ef 23 75 dc 1b 5b 94 99 e3 a3 2f ea 1b 4b c8 e4 2b 4b 7b 84 07 7b 6b fc e4 3e 97 04 29 4d 6b ec b8 4f 5b ec 0b 23 77 dc 1b 5b 94 99 ef a3 4b ea 1b 4b e8 28 2b e8 67 dc 1b 5b e0 d1 1f 7b 6b fc 12 b4 1f e7 71 4b 3c 04 41 4d 6b ec 98 8f 63 67 26 47 5b ec 0b}  //weight: 1, accuracy: High
        $x_1_2 = {55 f8 bd c5 11 68 ac 44 d6 0d 75 04 3d 25 4a 41 9e cb f7 44 57 cb 12 1f d6 3c df 44 80 d4 d3 b9 29 c3 36 80 de 0d 75 1b 88 67 e8 87 83 b5 50 c5 3a 2c b4 44 d6 6f e3 13 5d 49 bd fb 16 6c 32 79 5f c4 b4 bc 5f fb 73 c1 25 c2 4a bb d6 c3 b0 0c 21 7e b5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

