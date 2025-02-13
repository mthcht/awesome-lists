rule VirTool_Win32_Keser_A_2147604843_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Keser.gen!A"
        threat_id = "2147604843"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Keser"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {66 8b 43 06 8b 74 24 14 57 50 8d 46 f2 50 8d 43 08 50 e8 b6 ff ff ff 83 25 68 15 01 00 00 6a 08}  //weight: 4, accuracy: High
        $x_4_2 = {5a 83 c6 f8 3b f2 89 74 24 18 7e 5b 8d 34 1a 83 c9 ff 8b fe 33 c0 f2 ae f7 d1 49}  //weight: 4, accuracy: High
        $x_4_3 = {8b e9 81 fd e8 03 00 00 7f 42 a1 68 15 01 00 8b fe 6b c0 64 05 80 15 01 00 83 c9 ff}  //weight: 4, accuracy: High
        $x_4_4 = {89 44 24 14 33 c0 f2 ae f7 d1 2b f9 8d 54 2a 01 8b c1 8b f7 8b 7c 24 14 c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 ff 05 68 15 01 00 3b 54 24 18 7c a5 5f 5e 5d 5b}  //weight: 4, accuracy: High
        $x_6_5 = {0f bf 44 24 0c 56 33 f6 39 74 24 0c 7e 1a 50 e8 d2 ff ff ff 8b d0 8b 4c 24 08 03 ce c1 fa 08 30 11 46 3b 74 24 0c 7c e6}  //weight: 6, accuracy: High
        $x_1_6 = "ZwCreateFile" ascii //weight: 1
        $x_1_7 = "ZwClose" ascii //weight: 1
        $x_1_8 = "ZwQueryValueKey" ascii //weight: 1
        $x_1_9 = "ZwSetValueKey" ascii //weight: 1
        $x_1_10 = "ZwCreateKey" ascii //weight: 1
        $x_1_11 = "KeServiceDescriptorTable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 4 of ($x_4_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

