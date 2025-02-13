rule Backdoor_Linux_GTRevrs_A_2147810008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/GTRevrs.A!MTB"
        threat_id = "2147810008"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "GTRevrs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 11 44 24 38 0f 11 44 24 48 0f 11 44 24 58 48 c7 04 24 00 00 00 00 48 8d 05 ba cd 0a 00 48 89 44 24 08 48 c7 44 24 10 31 00 00 00 48 8b 05 99 ec 36 00 48 8b 0d 9a ec 36 00 48 89 44 24 18 48 89 4c 24 20 e8 f3 24 df ff 48 8b 44 24 28 48 8b 4c 24 30 48 89 44 24 38 48 89 4c 24 40 48 8b 05 e8 db 34 00 48 8b 0d e9 db 34 00 48 89 44 24 48 48 89 4c 24 50 48 8d 05 da a2 09 00 48 89 44 24 58 48 c7 44 24 60 03 00 00 00 0f 10 44 24 38 0f 11 04 24 0f 10 44 24 48 0f 11 44 24 10 0f 10 44 24 58 0f 11 44 24 20 e8 00 fe ff ff 48 8b 44 24 30 48 89 04 24 48 8d 05 ac 03 0a 00 48 89 44 24 08 48 c7 44 24 10 0d 00 00 00 e8 8d f9 ff ff 48 8b 44 24 20 48 8b 4c 24 18 48 89 4c 24 78 48 89 84 24 80 00 00 00 48 8b 6c 24 68}  //weight: 1, accuracy: High
        $x_1_2 = "/home/nuvm/GTRS/client.go" ascii //weight: 1
        $x_1_3 = {64 48 8b 0c 25 f8 ff ff ff 48 3b 61 10 0f 86 54 01 00 00 48 83 ec 60 48 89 6c 24 58 48 8d 6c 24 58 48 8b 4c 24 68 83 b9 40 01 00 00 ff 0f 85 fc 00 00 00 48 8b 54 24 78 48 89 d3 48 c1 e2 03 48 8d 42 05 48 89 44 24 48 48 ba ab aa aa aa aa aa aa aa 48 f7 ea 48 8d 54 da 05 48 8b 74 24 48 48 c1 fe 3f 48 c1 fa 02 48 29 f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

