rule Backdoor_Win64_MenialHarpoon_A_2147922590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/MenialHarpoon.A!dha"
        threat_id = "2147922590"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "MenialHarpoon"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 f1 31 d2 41 b8 0a 00 00 00 e8 ?? ?? ?? ?? 04 0a 48 8b 4d ?? 89 c2 e8 ?? ?? ?? ?? 48 89 f1 e8 ?? ?? ?? ?? 83 c7 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_MenialHarpoon_B_2147922591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/MenialHarpoon.B!dha"
        threat_id = "2147922591"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "MenialHarpoon"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 89 20 41 b8 0a 00 00 00 48 8d 54 24 ?? 48 8b cb ff 15 ?? ?? ?? ?? 44 8b c8 48 3b 5c 24 ?? 0f 84 ?? ?? ?? ?? 41 83 3e 22 0f 84 ?? ?? ?? ?? 41 80 c1 0a 48 8b 4f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

