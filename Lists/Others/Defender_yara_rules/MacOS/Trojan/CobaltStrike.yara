rule Trojan_MacOS_CobaltStrike_A_2147948602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/CobaltStrike.A!MTB"
        threat_id = "2147948602"
        type = "Trojan"
        platform = "MacOS: "
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 48 89 e5 41 57 41 56 41 55 41 54 53 48 81 ec 48 0b 00 00 48 8b 05 cd 72 32 00 48 8b 00 48 89 45 d0 8b 0d 58 66 35 00 81 f1 d4 00 00 00 48 83 ec 0a 50 68 e2 26 3d 67 31 c0 0f 84 01 00 00 00 c3}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 45 b0 8b 08 48 83 ec 0a 50 68 f1 6e 9e 31 31 c0 0f 84 01 00 00 00 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_CobaltStrike_B_2147956176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/CobaltStrike.B!MTB"
        threat_id = "2147956176"
        type = "Trojan"
        platform = "MacOS: "
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main/c0md.parseCommandUpload" ascii //weight: 1
        $x_1_2 = "main/c0md.SpawnAndInjectDll" ascii //weight: 1
        $x_1_3 = "main/c0md.KillProcess" ascii //weight: 1
        $x_1_4 = "main/c0md.StealToken" ascii //weight: 1
        $x_1_5 = "main/c0md.parseCommandShell" ascii //weight: 1
        $x_1_6 = "main/c0md.Upload" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

