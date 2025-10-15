rule HackTool_Linux_Shaco_A_2147955211_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Shaco.A!MTB"
        threat_id = "2147955211"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Shaco"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "shaco_http_post" ascii //weight: 1
        $x_1_2 = "shaco_free" ascii //weight: 1
        $x_1_3 = {bf 02 00 00 00 4c 89 e6 ba 41 02 00 00 b9 a4 01 00 00 31 c0 e8 47 d5 ff ff 49 89 c4 bd 00 00 00 01 45 85 e4 78 2d bf 01 00 00 00 44 89 e6 4c 89 fa 4c 89 f1 31 c0 e8 25 d5 ff ff 48 85 c0 0f 88 de 00 00 00 bf 03 00 00 00 44 89 e6 31 c0}  //weight: 1, accuracy: High
        $x_1_4 = {48 83 c0 13 ba 00 08 00 00 48 89 ef 31 f6 48 89 c5 e8 44 f4 ff ff be 00 08 00 00 ba 8b 30 4c 00 48 8d 7c 24 60 48 89 e9 48 8d 6c 24 60 31 c0 e8 7e 1a 00 00 bf 02 00 00 00 48 89 ee 31 d2 31 c9 31 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

