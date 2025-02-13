rule HackTool_Linux_Sliver_A_2147810006_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Sliver.A!MTB"
        threat_id = "2147810006"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Sliver"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 8d 64 24 f8 4d 3b 66 10 0f 86 2f 05 00 00 48 81 ec 88 00 00 00 48 89 ac 24 80 00 00 00 48 8d ac 24 80 00 00 00 48 89 84 24 90 00 00 00 48 89 9c 24 98 00 00 00 48 85 c0 0f 84 d4 04 00 00 8b 48 10 81 f9 6d 54 1a b3 0f 87 57 02 00 00 81 f9 8c 02 25 79 0f 87 30 01 00 00 66 0f 1f 44 00 00 81 f9 fb 7f a2 2e 0f 87 83 00 00 00 81 f9 c5 06 ff 13 75 36}  //weight: 1, accuracy: High
        $x_1_2 = {49 3b 66 10 0f 86 e9 00 00 00 48 83 ec 40 48 89 6c 24 38 48 8d 6c 24 38 48 ba a3 e0 84 65 9e 46 a4 9c 48 89 54 24 1f 48 ba 65 9e 46 a4 9c 84 d0 a8 48 89 54 24 22 48 ba 01 05 06 01 08 02 07 09 48 89 54 24 2a 48 ba 07 09 0a 0a 00 01 00 04 48 89 54 24 30 31 c0 eb 1a 44 0f b6 4c 34 1f 41 8d 14 11 8d 52 8e 88 54 3c 1f 44 88 44 34 1f 48 83}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

