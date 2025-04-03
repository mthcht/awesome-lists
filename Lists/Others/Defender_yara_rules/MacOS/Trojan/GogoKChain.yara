rule Trojan_MacOS_GogoKChain_A_2147937781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/GogoKChain.A!MTB"
        threat_id = "2147937781"
        type = "Trojan"
        platform = "MacOS: "
        family = "GogoKChain"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 ec 38 48 89 d3 4c 8b 35 70 33 00 00 4c 8b 3d 41 1b 00 00 48 89 cf 41 ff d7 48 89 45 a8 48 89 df 41 ff d7 49 89 c4 4c 89 f7 e8 32 09 00 00 48 8b 35 8f 32 00 00 4c 8b 3d 08 1b 00 00 48 89 c7 41 ff d7 48 8b 35 d3 32 00 00 48 8d 15 34 1f 00 00 48 89 c7 48 89 c3}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 3d 14 33 00 00 48 8b 35 ed 32 00 00 48 8d 15 36 1f 00 00 4c 89 e1 31 c0 41 ff d7 48 89 c7 e8 f4 08 00 00 48 89 45 a0 48 8b 3d fb 32 00 00 48 8b 35 ec 31 00 00 48 8d 15 2d 1f 00 00 48 89 c1 45 31 c0 31 c0 41 ff d7 48 89 c7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

