rule Backdoor_Linux_Ganiw_A_2147824646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Ganiw.A!xp"
        threat_id = "2147824646"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Ganiw"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CUpdateBill" ascii //weight: 1
        $x_1_2 = "CAttackUdp" ascii //weight: 1
        $x_1_3 = "CUpdateGates" ascii //weight: 1
        $x_1_4 = "CFakeDetectPayload" ascii //weight: 1
        $x_1_5 = "CAttackCc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Ganiw_B_2147825980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Ganiw.B!xp"
        threat_id = "2147825980"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Ganiw"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 89 e5 57 56 53 83 ec 2c 8b 45 0c 8b 55 18 8b 4d 1c 8b 5d 20 8b 75 24 88 45 e0 66 89 55 dc 88 4d d8 66 89 5d d4 89 f0 88 45 d0 8b 45 08 89 45 e4 8a 45 e0 83 f0 01 84 c0}  //weight: 1, accuracy: High
        $x_1_2 = {55 89 e5 83 ec 08 e8 00 00 00 00 5a 81 c2 39 95 0e 00 b8 64 7d 0d 0a 08 85 c0 74 15 52 6a 00 68 e4 2b 13 08 68 40 c7 11 08 e8 83 fb 05 00 83 c4 10 a1 48 10 13 08 85 c0 74 16 b8 00 00 00 00 85 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

