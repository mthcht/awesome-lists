rule VirTool_Win64_RevShellSim_C_2147940205_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/RevShellSim.C"
        threat_id = "2147940205"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "RevShellSim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 28 00 00 00 00 c7 44 24 20 00 00 00 00 41 b9 00 00 00 00 41 b8 ?? ?? ?? ?? ba 01 00 00 00 b9 02 00 00 00 48 8b 05 ?? ?? ?? ?? ff d0 48 8b 95 70 01 00 00 48 89 02 48 8b 85 70 01 00 00 48 8b 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 c7 44 24 28 00 00 00 00 c7 44 24 20 00 00 00 00 41 b9 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ba 00 00 00 00 b9 00 00 00 00 48 8b 05 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 85 70 01 00 00 48 8b 00 ?? ?? ?? ?? 41 b8 ?? ?? ?? ?? 48 89 c1 48 8b 05 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
        $x_1_4 = {48 89 44 24 40 48 c7 44 24 38 00 00 00 00 48 c7 44 24 30 00 00 00 00 c7 44 24 28 ?? ?? ?? ?? c7 44 24 20 ?? ?? ?? ?? 41 b9 00 00 00 00 41 b8 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 c2 b9 00 00 00 00 48 8b 05 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_RevShellSim_D_2147941247_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/RevShellSim.D"
        threat_id = "2147941247"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "RevShellSim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b8 10 00 00 00 48 89 c1 48 8b ?? ?? ?? ?? ?? ff d0 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 44 24 28 00 00 00 00 c7 44 24 20 00 00 00 00 41 b9 00 00 00 00 41 b8 ?? ?? ?? ?? ba 01 00 00 00 b9 02 00 00 00 48 8b 05 ?? ?? ?? ?? ff d0 48 8b 95 70 01 00 00 48 89 02 48 8b 85 70 01 00 00 48 8b 00}  //weight: 1, accuracy: Low
        $x_1_3 = {48 c7 44 24 28 00 00 00 00 c7 44 24 20 00 00 00 00 41 b9 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ba 00 00 00 00 b9 00 00 00 00 48 8b 05 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
        $x_1_4 = {48 89 44 24 40 48 c7 44 24 38 00 00 00 00 48 c7 44 24 30 00 00 00 00 c7 44 24 28 ?? ?? ?? ?? c7 44 24 20 ?? ?? ?? ?? 41 b9 00 00 00 00 41 b8 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 c2 b9 00 00 00 00 48 8b 05 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
        $x_1_5 = "FP_NO_HOST_CHECK" ascii //weight: 1
        $x_1_6 = "\\\\.\\pipe\\" ascii //weight: 1
        $x_1_7 = "SDL_DrawLine()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

