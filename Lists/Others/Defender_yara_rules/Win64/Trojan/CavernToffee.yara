rule Trojan_Win64_CavernToffee_A_2147891623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CavernToffee.A!dha"
        threat_id = "2147891623"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CavernToffee"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 4c 8d 35 ?? ?? ?? ?? 41 bc ?? ?? ?? ?? 42 80 34 30 ?? 48 ff c0 49 3b c4 72 f3}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 4c 8d 3d ?? ?? ?? ?? 42 80 34 38 ?? 48 ff c0 48 3d ?? 00 00 00 72 f0}  //weight: 1, accuracy: Low
        $x_1_3 = {4e 74 41 6c c7 45 ?? 6c 6f 63 61 c7 45 ?? 74 65 56 69 c7 45 ?? 72 74 75 61 c7 45 ?? 6c 4d 65 6d c7 45 ?? 6f 72 79 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CavernToffee_D_2147891624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CavernToffee.D!dha"
        threat_id = "2147891624"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CavernToffee"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 8b c3 48 8d 15 ?? ?? ?? ?? 48 8b c8 48 8b f0 e8 ?? ?? ?? ?? 48 8b ce 80 31 ?? 48 ff c1 48 83 eb 01 75 f4}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 c7 45 ?? 74 65 54 68 c7 45 ?? 72 65 61 64 88 5d ?? e8 ?? ?? ?? ?? 48 21 5c 24 ?? 4c 8b cf 21 5c 24 ?? 4c 8b c6 33 d2 33 c9 ff d0 48 8b d8 48 83 f8 ff 74 1c 48 8d 4d ?? c7 45 ?? 4e 74 43 6c c7 45 ?? 6f 73 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CavernToffee_E_2147891625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CavernToffee.E!dha"
        threat_id = "2147891625"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CavernToffee"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 44 00 48 8d 55 ?? 66 44 89 75 ?? 48 8d 4d ?? c7 45 ?? 65 00 76 00 c7 45 ?? 69 00 63 00 c7 45 ?? 65 00 5c 00 c7 45 ?? 48 00 74 00 c7 45 ?? 74 00 70 00 c7 45 ?? 5c 00 43 00 c7 45 ?? 6f 00 6d 00 c7 45 ?? 6d 00 75 00 c7 45 ?? 6e 00 69 00 c7 45 ?? 63 00 61 00 c7 45 ?? 74 00 69 00 c7 45 ?? 6f 00 6e 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

