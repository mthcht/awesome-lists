rule VirTool_Linux_Myrddyn_A_2147821103_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Linux/Myrddyn.A!MTB"
        threat_id = "2147821103"
        type = "VirTool"
        platform = "Linux: Linux platform"
        family = "Myrddyn"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 4c 24 40 48 8b 54 24 18 41 b8 01 00 00 00 48 83 7a 28 00 74 2d e8 ?? ?? 05 00 45 0f 57 ff 64 4c 8b 34 25 f8 ff ff ff 48 8b 04 24 48 8b 4c 24 18 48 89 41 28 48 89 ca 41 b8 01 00 00 00 48 8b 4c 24 40 48 8b 32 84 06 83 3d 7a fb 86 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 85 d2 0f 84 8f 01 00 00 48 89 54 24 18 48 8b 5a 18 ?? 48 85 db 74 41 48 8b 41 20 e8 ?? ?? 00 00 83 3d ab bc 86 00 00 75 0f 48 8b 4c 24 18 48 c7 41 18 00 00 00 00 eb 10 48 8b 4c 24 18}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 51 48 0f 1f 40 00 48 85 d2 0f ?? ?? ff ff ff 48 8d 79 48 48 8b 5a 08 48 85 db 74 ?? 83 3d 43 ba 86 00 00 75 16 48 c7 43 10 00 00 00 00 48 89 59 48 48 c7 42 08 00 00 00 00 eb ?? 48 8d 73 10}  //weight: 1, accuracy: Low
        $x_1_4 = {48 8b 44 24 30 48 8d 48 08 48 8b 54 24 40 48 89 0c 24 48 89 54 24 08 e8 ?? ?? 00 00 48 8b 44 24 38 48 8b 4c 24 30 48 89 0c 24 48 89 44 24 08 e8 ?? ?? 00 00 e8 cd b3 03 00 48 8b 6c 24 20 48 83 c4 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

