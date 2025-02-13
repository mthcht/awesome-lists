rule VirTool_Win32_Tinmetz_A_2147782218_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Tinmetz.A!MTB"
        threat_id = "2147782218"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinmetz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 e4 f8 81 ec ac 01 00 00 a1 ?? ?? ?? ?? 33 c4 89 84 24 a8 01 00 00 53 8b 1d ?? ?? ?? ?? 8d ?? ?? ?? 56 8b 35 ?? ?? ?? ?? 57 50 68 02 02 00 00 33 ff ff 15 ?? ?? ?? ?? 85 c0 ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 04 6a 01 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 6a 04 68 ?? ?? ?? ?? 53 ff 15 60 20 40 00 a1 ?? ?? ?? ?? 6a 40 68 00 10 00 00 83 c0 05 50 6a 00 ff 15 00 20 40 00 a3 ?? ?? ?? ?? c6 00 bf 89 58 01 8b 35 ?? ?? ?? ?? 85 f6 ?? ?? 0f 1f 44 00 00 6a 00 83 c0 05 56 03 c7 50 53 ff 15 ?? ?? ?? ?? 03 f8 2b f0 a1 ?? ?? ?? ?? ?? ?? 8b 8c 24 b4 01 00 00 5f 5e 5b 33 cc e8 ?? ?? ?? ?? 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 40 0c 53 8b 00 8b 00 a3 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 83 c4 04 50 ff 15 ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 6a 00 89 4c 24 18 b9 02 00 00 00 6a 01 51 66 a3 ?? ?? ?? ?? 66 89 4c 24 1c 66 89 44 24 1e ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Tinmetz_C_2147782826_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Tinmetz.C!MTB"
        threat_id = "2147782826"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinmetz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c1 e8 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {41 b9 00 00 00 00 41 b8 04 00 00 00 48 8d [0-5] 48 89 c1 48 8b 05 ?? ?? ?? ?? ff d0 [0-7] 83 c0 05 [0-1] 89 c0 41 b9 40 00 00 00 41 b8 00 10 00 00 48 89 c2 b9 00 00 00 00 48 8b 05 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
        $x_1_3 = {41 b8 00 00 00 00 ba 01 00 00 00 b9 02 00 00 00 48 8b 05 ?? ?? ?? ?? ff d0 48 89 85 ?? ?? ?? ?? 48 83 bd 01 ff [0-32] 48 8d 45 ?? 48 8b 8d 01 41 b8 10 00 00 00 48 89 c2 48 8b 05 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

