rule HackTool_Linux_Chaos_A_2147810005_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Chaos.A!MTB"
        threat_id = "2147810005"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Chaos"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/client/app/services/screenshot/screenshot_service.go" ascii //weight: 1
        $x_1_2 = {75 54 48 8b 08 48 83 78 08 05 75 4a 81 39 77 72 69 74 75 42 80 79 04 65 75 3c 48 8b 48 10 48 83 78 18 02 75 31 66 81 39 7c 31 75 2a 48 8b 48 20 48 8b 40 28 48 85 c9 74 19 48 8d 15 0a 96 04 00 48 39 51 08 75 0c 48 83 38 20 0f 94 c0}  //weight: 1, accuracy: High
        $x_1_3 = "/tiagorlampert/CHAOS/client/app" ascii //weight: 1
        $x_1_4 = {64 48 8b 04 25 f8 ff ff ff 48 8b 40 30 8b 88 20 01 00 00 8b 90 24 01 00 00 89 90 20 01 00 00 89 cb c1 e1 11 31 d9 89 d3 31 ca c1 e9 07 31 d1 89 da c1 eb 10 31 cb 89 98 24 01 00 00 8d 04 1a 48 8b 4c 24 38 48 31 c8 48 b9 21 a6 56 6a a1 6e 75 00 48 31 c1 48 b8 bf 63 8f bb 6b ef 52 00 48 0f af c8 48 89 4c 24 40 48 8b 6c 24 20 48 83 c4 28 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

