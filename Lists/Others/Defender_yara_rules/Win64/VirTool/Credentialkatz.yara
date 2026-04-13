rule VirTool_Win64_Credentialkatz_A_2147966878_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Credentialkatz.A"
        threat_id = "2147966878"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Credentialkatz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 89 65 e0 4c 8b f0 48 85 c0 [0-16] 4d 8b ce ?? ?? ?? ?? ?? 48 89 44 24 20 48 8b cb e8 ?? ?? ?? ?? 85 c0 ?? ?? ?? ?? ?? ?? 48 8b 75 e0}  //weight: 1, accuracy: Low
        $x_1_2 = {49 8b 14 fe 48 85 d2 ?? ?? ?? ?? ?? ?? 48 83 c2 20 4c 89 64 24 20 41 b9 18 00 00 00 ?? ?? ?? ?? 48 8b cb ff ?? ?? ?? ?? ?? 85 c0 ?? ?? 48 8b 55 f8 ?? ?? ?? ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 8b f0 e8 ?? ?? ?? ?? 85 c0 ?? ?? ?? ?? ?? ?? 44 8b 44 24 58 33 d2 b9 10 04 00 00 ff ?? ?? ?? ?? ?? 8b 54 24 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

