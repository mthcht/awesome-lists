rule VirTool_Win64_Credumpesz_A_2147922941_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Credumpesz.A!MTB"
        threat_id = "2147922941"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Credumpesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 8b c7 33 d2 b9 00 00 00 02 ?? ?? ?? ?? ?? ?? 48 8b d8 48 85 c0 [0-17] 48 c7 44 24 30 00 00 00 00 ba 0e 00 00 00 48 8b c8 ?? ?? ?? ?? ?? ?? 85 c0 ?? ?? 48 8b 4c 24 30}  //weight: 1, accuracy: Low
        $x_1_2 = {40 53 55 56 57 41 54 41 55 41 56 41 57 48 81 ec a8 0c 00 00 48 8b 05 65 4b 02 00 48 33 c4 48 89 84 24 ?? 0c 00 00 4c 8b bc 24 10 0d 00 00 4d 8b f0 4c 8b a4 24 18 0d 00 00 8b f2 4c 8b ac 24 20 0d 00 00 48 8b e9 44 89 4c 24 30 44 8b ca 4c 89 44 24 28 ba 00 04 00 00 48 89 4c 24 20}  //weight: 1, accuracy: Low
        $x_1_3 = {ba 00 04 00 00 [0-32] 80 3d 18 66 02 00 00 ?? ?? ?? ?? ?? ?? ?? ?? c6 05 09 66 02 00 01 [0-16] 80 3d f8 65 02 00 00 ?? ?? ?? ?? ?? ?? ?? ?? c6 05 e9 65 02 00 01 [0-25] 48 83 3d be 65 02 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 8b cb}  //weight: 1, accuracy: Low
        $x_1_4 = {48 8b 44 24 38 ?? ?? ?? ?? ?? 48 8b 4c 24 30 41 b9 10 00 00 00 48 c7 44 24 28 00 00 00 00 33 d2 48 89 44 24 44 c7 44 24 40 01 00 00 00 c7 44 24 4c 02 00 00 00 48 c7 44 24 20 00 00 00 00 ?? ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

