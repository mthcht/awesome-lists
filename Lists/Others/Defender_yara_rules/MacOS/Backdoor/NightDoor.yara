rule Backdoor_MacOS_NightDoor_A_2147932200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/NightDoor.A!MTB"
        threat_id = "2147932200"
        type = "Backdoor"
        platform = "MacOS: "
        family = "NightDoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 85 28 ff ff ff 48 8b 3d 8d 8f 00 00 48 8b 35 8e 8d 00 00 4c 8b 2d cf 37 00 00 41 ff d5 48 89 c7 e8 d8 12 00 00 48 8b 35 cd 8e 00 00 48 89 85 30 ff ff ff 48 89 c7 41 ff d5 48 8b 3d 31 8f 00 00 48 8b 35 9a 8e 00 00 41 ff d5 48 89 c7 e8 c3 12 00 00 48 8b 3d 30 8f 00 00 48 8b 35 31 8c 00 00 41 ff d5 48 89 c7 e8 92 12 00 00 49 89 c4 48 8b 3d 74 8f 00 00 4c 8b 35 ad 8b 00 00 4c 89 f6 41 ff d5 48 89 c7 e8 73 12 00 00 48 89 c3 48 8b 35 cd 8b 00 00 48 8d 15 86 3e 00 00 48 89 c7 41 ff d5 41 89 c7 48 89 df ff 15 64 37 00 00 45 84 ff 74 37 48 8b 3d 30 8f 00 00 4c 89 f6 41 ff d5 48 89 c7 e8 36 12 00 00 48 89 c3 48 8b 35 20 8d 00 00 48}  //weight: 1, accuracy: High
        $x_1_2 = {55 48 89 e5 41 57 41 56 41 54 53 49 89 fe 48 8b 3d 7e 8b 00 00 48 8b 35 57 87 00 00 ff 15 31 33 00 00 48 89 c7 e8 3d 0e 00 00 48 89 c3 49 8b 46 20 48 8b 78 08 48 8b 57 28 48 85 d2 74 65 48 8b 35 56 8a 00 00 48 89 df ff 15 05 33 00 00 66 0f 57 c9 66 0f 2e c8 77 43 66 0f 2e 05 6b 2e 00 00 76 4d 48 8b 3d b2 8a 00 00 48 8b 35 db 89 00 00 4c 8b 25 dc 32 00 00 41 ff d4 48 89 c7 e8 e5 0d 00 00 49 89 c7 48 8b 35 0f 89 00 00 48 89 c7 41 ff d4 4c 89 ff ff 15 e0 32 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "/tmp/perfname.nat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

