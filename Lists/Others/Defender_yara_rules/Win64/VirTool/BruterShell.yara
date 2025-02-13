rule VirTool_Win64_BruterShell_A_2147899111_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/BruterShell.A"
        threat_id = "2147899111"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "BruterShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 c9 ba 26 25 19 3e 49 89 c0 e8 ?? ?? ?? ?? 44 8d 43 01}  //weight: 1, accuracy: Low
        $x_1_2 = {41 80 f8 4c [0-16] 80 79 01 8b 75 ?? 80 79 02 d1 75 ?? 41 80 f9 b8 75 ?? 80 79 06 00}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 8b 03 ba bd ca 3b d3 48 89 d9 48 89 84 24 ?? 00 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {48 c7 c2 ff ff ff ff c7 44 24 ?? 04 00 00 00 c7 44 24 ?? 00 30 00 00 [0-16] e8}  //weight: 1, accuracy: Low
        $x_1_5 = {ba b8 0a 4c 53 e8}  //weight: 1, accuracy: High
        $x_1_6 = {ba 89 4d 39 8c 48 89 84 24 ?? ?? 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_BruterShell_A_2147899111_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/BruterShell.A"
        threat_id = "2147899111"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "BruterShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 80 f8 4c [0-16] 80 79 01 8b 75 ?? 80 79 02 d1 75 ?? 41 80 f9 b8 75 ?? 80 79 06 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 c7 c2 ff ff ff ff c7 44 24 ?? 04 00 00 00 c7 44 24 ?? 00 30 00 00 [0-16] e8}  //weight: 1, accuracy: Low
        $x_1_3 = {ba b8 0a 4c 53 e8}  //weight: 1, accuracy: High
        $x_1_4 = {ba 89 4d 39 8c 48 89 84 24 ?? ?? 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_5 = {ba 29 44 e8 57 [0-16] e8 [0-16] ba 0e e8 4b 1e [0-16] e8}  //weight: 1, accuracy: Low
        $x_1_6 = {48 b8 3a 7b 22 61 75 74 68 22 [0-32] c7 84 24 ?? ?? 00 00 50 4f 53 54}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

