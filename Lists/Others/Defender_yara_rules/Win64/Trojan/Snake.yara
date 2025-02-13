rule Trojan_Win64_Snake_A_2147847175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Snake.A!dha"
        threat_id = "2147847175"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Snake"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 81 7d 07 a1 72 2d 00 0f 94 c0 84 c0 75}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Snake_B_2147847176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Snake.B!dha"
        threat_id = "2147847176"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Snake"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d2 41 b8 00 80 00 00 [0-6] ff 15 [0-3] ff ?? ?? ?? 4c 8d 44 24 ?? 48 8d 54 24 ?? 8b ?? e8 ?? ?? ff ff 85 c0 74 (bc|bd)}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Snake_E_2147847177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Snake.E!dha"
        threat_id = "2147847177"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Snake"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {75 0c b8 66 00 59 21 48 83 c4 60 41 5d c3 48 85 d2 75 0c b8 67 00 59 21 48 83 c4 60 41 5d c3 4d 85 c0 75 0c b8 68 00 59 21 48 83 c4 60 41 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

