rule Backdoor_MacOS_RShell_A_2147839940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/RShell.A!MTB"
        threat_id = "2147839940"
        type = "Backdoor"
        platform = "MacOS: "
        family = "RShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 3d 73 4b 01 00 48 8d 35 21 31 01 00 ba 19 00 00 00 e8 c0 84 ff ff 48 89 c3 48 8b 00 48 8b 70 e8 48 01 de 48 8d 7d c0 e8 f6 e8 00 00 48 8b 35 4d 4b 01 00 48 8d 7d c0 e8 e0 e8 00 00 48 8b 08 48 89 c7 be 0a 00 00 00 ff 51 38 41 89 c5 48 8d 7d c0 e8 8c e9 00 00 41 0f be f5 48 89 df e8 44 e9 00 00 48 89 df}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MacOS_RShell_B_2147839941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/RShell.B!MTB"
        threat_id = "2147839941"
        type = "Backdoor"
        platform = "MacOS: "
        family = "RShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 df e8 95 ?? ?? ?? 48 8d 35 87 30 01 00 48 8d bd 50 ?? ?? ?? e8 d6 04 00 00 48 8d 35 25 2f 01 00 48 8d 7d b0 e8 10 ec ff ff 48 89 c3 4c 8d a5 50 ?? ?? ?? 4c 89 e7 e8 60 ?? ?? ?? 8a 03 41 8a 0c 24 88 0b 41 88 04 24 4c 8d ad 58 ?? ?? ?? 48 8b 43 08 49 8b 4d 00 48 89 4b 08 49 89 45 00 48 89 df e8 35 ?? ?? ?? 4c 89 e7 e8 2d ?? ?? ?? 41 0f b6 75 f8 4c 89 ef e8 cc f4 ff ff 48 8d 7d c0 e8 c4 ca fe ff 48 8d bd 60 ?? ?? ?? 48 8d 75 c0 e8 27 ed ff ff 48 8d 35 ff 2f 01 00 48 8d 7d b0 e8 95 eb ff ff 48 89 c3 4c 8d a5 60 ?? ?? ?? 4c 89 e7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

