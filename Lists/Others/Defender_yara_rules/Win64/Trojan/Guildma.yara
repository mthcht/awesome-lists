rule Trojan_Win64_Guildma_2147838532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Guildma.psyR!MTB"
        threat_id = "2147838532"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Guildma"
        severity = "Critical"
        info = "psyR: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {15 25 00 48 00 6f 00 6d 00 65 00 50 00 61 00 74 00 68 00 25 00 00 15 25 00 48 00 4f 00 4d 00 45 00 50 00 41 00 54 00 48 00 25 00 00 0d 50 00 55 00 42 00 4c 00 49 00 43 00 00 11 25 00 50 00 75 00 62 00 6c 00 69 00 63 00 25 00 00 11 25}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Guildma_2147840580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Guildma.psyP!MTB"
        threat_id = "2147840580"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Guildma"
        severity = "Critical"
        info = "psyP: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {41 51 41 50 52 48 31 d2 65 48 8b 52 60 51 48 8b 52 18 56 48 8b 52 20 48 8b 72 50 4d 31 c9 48 0f b7 4a 4a 48 31 c0 ac 3c 61 7c 02 2c 20 41 c1 c9 0d 41 01 c1 e2 ed 52 41 51}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

