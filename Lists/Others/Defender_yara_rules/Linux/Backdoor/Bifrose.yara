rule Backdoor_Linux_Bifrose_JJ_2147781121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Bifrose.JJ"
        threat_id = "2147781121"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Bifrose"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 80 00 00 00 85 c0 75 37 8b 45 f0 89 c1 03 4d 08 8b 45 f0 03 45 08 0f b6 10 8b 45 f8 01 c2 b8 ff ff ff ff 21 d0 88 01 8b 45 f0 89 c2 03 55 08 8b 45 f0 03 45 08 0f b6 00 32 45 fd 88 02}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 f0 03 45 08 0f b6 00 30 45 fd 8b 45 f0 89 c1 03 4d 08 8b 45 f8 89 c2 02 55 fd b8 ff ff ff ff 21 d0 88 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Bifrose_B_2147905472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Bifrose.B!MTB"
        threat_id = "2147905472"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Bifrose"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c7 45 c4 ff ff ff ff 83 ec 0c 68 ?? ?? ?? 08 e8 ?? ?? ?? ?? 83 c4 10 83 ec 04 6a 06 6a 01 6a 02 e8 ?? ?? ?? ?? 83 c4 10 89 45 c4 83 7d c4 00 79 12 83 ec 0c 6a 0a e8 ?? ?? ?? ?? 83 c4 10 e9}  //weight: 5, accuracy: Low
        $x_5_2 = {48 63 05 56 55 20 00 48 6b c0 3e 4a 8d 14 28 41 0f bf 4c 05 3c bf b8 5d 40 00 31 c0 e8 ?? ?? ?? ?? bf c4 5d 40 00 31 c0 e8 ?? ?? ?? ?? bf 02 00 00 00 be 01 00 00 00 ba 06 00 00 00 e8 ?? ?? ?? ?? 41 89 c4 45 85 e4}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

