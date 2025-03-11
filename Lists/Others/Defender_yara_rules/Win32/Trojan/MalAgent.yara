rule Trojan_Win32_MalAgent_NIT_2147935598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MalAgent.NIT!MTB"
        threat_id = "2147935598"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MalAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c7 85 d0 fd ff ff 2c 02 00 00 e8 48 06 00 00 8b f0 83 fe ff 75 11 33 c0 5e 8b 4d fc 33 cd e8 7f 06 00 00 8b e5 5d c3 57 8d 85 d0 fd ff ff 50 56 e8 28 06 00 00 85 c0 74 4f 8b 7d 08 8b c7 8d 8d f4 fd ff ff 0f 1f 40 00 66 8b 11 66 3b 10 75 1e 66 85 d2 74 15 66 8b 51 02 66 3b 50 02 75 0f 83 c1 04 83 c0 04 66 85 d2 75 de 33 c0 eb 05 1b c0 83 c8 01 85 c0 74 2a 8d 85 d0 fd ff ff 50 56 e8 df 05 00 00 85 c0 75 b4}  //weight: 2, accuracy: High
        $x_2_2 = {ff 15 04 c0 44 00 85 c0 75 36 50 50 8d 85 54 fd ff ff 50 6a 00 68 40 c2 44 00 ff b5 50 fd ff ff ff 15 00 c0 44 00 ff b5 50 fd ff ff 8b f0 ff 15 08 c0 44 00 85 f6 74 31 81 fe ea 00 00 00 74 29 6a 00 68 7c c2 44 00 e8 eb be 00 00 83 c4 08 83 f8 ff 74 15 6a 00 6a 00 6a 00 68 80 11 40 00 6a 00 6a 00 ff 15 18 c0 44 00 68 f1 c1 44 00}  //weight: 2, accuracy: High
        $x_1_3 = "ziliao.jpg" ascii //weight: 1
        $x_1_4 = "chuangkou.log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

