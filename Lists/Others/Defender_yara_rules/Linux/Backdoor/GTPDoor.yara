rule Backdoor_Linux_GTPDoor_A_2147906105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/GTPDoor.A!MTB"
        threat_id = "2147906105"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "GTPDoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 fc 48 98 48 89 c1 48 03 4d c8 0f b6 45 fb 48 03 45 e8 0f b6 10 8b 45 fc 48 98 48 03 45 d8 0f b6 00 31 d0 88 01 80 45 fb 01 83 45 fc 01 0f b7 45 d4 3b 45 fc 7f ?? 0f b7 45 d4}  //weight: 5, accuracy: Low
        $x_5_2 = {8b 45 fc 89 c1 03 4d 18 0f b6 45 fb 03 45 08 0f b6 10 8b 45 fc 03 45 10 0f b6 00 31 d0 88 01 80 45 fb 01 83 45 fc 01 0f b7 45 e8 3b 45 fc 7f ?? 0f b7 45 e8}  //weight: 5, accuracy: Low
        $x_1_3 = "myDecryptFun" ascii //weight: 1
        $x_1_4 = "remoteExec" ascii //weight: 1
        $x_1_5 = "sendResult2Peer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

