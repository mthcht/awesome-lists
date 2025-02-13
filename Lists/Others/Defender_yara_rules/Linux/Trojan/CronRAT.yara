rule Trojan_Linux_CronRAT_A_2147808785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/CronRAT.A!MTB"
        threat_id = "2147808785"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "CronRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {49 89 c5 31 c0 8a 14 06 32 14 01 41 88 54 05 00 48 ff c0 48 83 f8 06 75 ec bf 01 00 00 00 be 0a 00 00 00 4c 89 ac 24 c0 01 00 00 e8 ?? ?? ?? 00 31 d2 48 89 c7 8a 44 15 00 41 32 04 14 88 04 17 48 ff c2 48 83 fa 09 75 ec be 01 00 00 00 48 89 bc 24 c8 01 00 00 e8 b8 a6 ff ff 48 89 c5}  //weight: 2, accuracy: Low
        $x_2_2 = {48 85 ff 75 25 be 01 00 00 00 4c 89 c7 e8 bc 5d 01 00 48 8d 50 10 48 89 58 08 48 89 15 c4 d8 01 00 48 c7 00 00 00 00 00 eb 1b 48 83 ef 10 4c 89 c6 e8 30 54 01 00 48 8d 50 10 48 89 58 08 48 89 15 a0 d8 01 00 48 8b 15 99 d8 01 00 31 c0 48 85 d2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

