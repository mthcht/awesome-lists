rule Trojan_Win32_Swomanso_AA_2147758678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Swomanso.AA!MTB"
        threat_id = "2147758678"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Swomanso"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 06 46 85 c0 74 3d bb 00 00 00 00 89 7d f4 2b 7d f4 09 f7 83 e2 00 31 fa 8b 7d f4 51 c7 04 e4 08 00 00 00 8f 45 fc d1 c0 8a fc 8a e6 d1 cb ff 4d fc 75 f3 89 4d f8 83 e1 00 31 d9 83 e0 00 31 c8 8b 4d f8 aa 49 75 b7}  //weight: 1, accuracy: High
        $x_1_2 = {89 7d e4 83 e7 00 0b 7d e8 83 e2 00 09 fa 8b 7d e4 d3 c2 23 d3 ac 0a c2 88 07 47 ff 4d f8 75 b9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

