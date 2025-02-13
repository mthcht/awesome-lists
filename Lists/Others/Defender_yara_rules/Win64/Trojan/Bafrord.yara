rule Trojan_Win64_Bafrord_A_2147735241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bafrord.A!dha"
        threat_id = "2147735241"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bafrord"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 b2 02 00 00 44 8b c1 [0-2] 41 8b d0 66 42 39 04 0a 75 0b 41 83 c0 02 43 80 3c 08 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 83 c1 fd 4c 03 c1 49 03 c0 4c 89 05 ?? ?? 00 00 48 89 42 08 4c 89 02 48 8b 0d ?? ?? 00 00 48 c7 c2 fd ff ff ff ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bafrord_B_2147739978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bafrord.B!dha"
        threat_id = "2147739978"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bafrord"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 b2 02 00 00 [0-5] 41 8b d0 66 42 39 04 0a 75 0b 41 83 c0 02 43 80 3c 08 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 83 c1 fd [0-20] 4c 03 c1 [0-7] 49 03 c0 [0-7] 48 89 42 08 4c 89 02 [0-7] 48 c7 c2 fd ff ff ff [0-7] ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

