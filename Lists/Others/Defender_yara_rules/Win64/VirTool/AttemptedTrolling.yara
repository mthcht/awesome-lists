rule VirTool_Win64_AttemptedTrolling_A_2147947823_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/AttemptedTrolling.A"
        threat_id = "2147947823"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "AttemptedTrolling"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 8b c7 33 d2 b9 38 0e 00 00 ff 15 ?? ?? ?? ?? 48 8b 4c 24 30 48 89 44 24 30}  //weight: 1, accuracy: Low
        $x_1_2 = {bb 0c 00 00 00 44 8b cb ?? ?? ?? ?? ?? ?? ?? 48 8b 15 ?? ?? ?? ?? 48 8b 4c 24 30 ff 15 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 44 24 20 ?? ?? ?? 44 8b cf 4c 8b 44 24 48 48 8b 15 ?? ?? ?? ?? 48 8b 4c 24 30 ff 15 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_4 = {48 89 74 24 20 4c 8b 4c 24 48 4c 8b 44 24 78 48 8b 15 ?? ?? ?? ?? 48 8b 4c 24 30 ff 15 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

