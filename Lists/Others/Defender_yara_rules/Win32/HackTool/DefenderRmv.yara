rule HackTool_Win32_DefenderRmv_A_2147827461_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/DefenderRmv.A"
        threat_id = "2147827461"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DefenderRmv"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Defender Remover" ascii //weight: 1
        $x_1_2 = "RunProgram=\"run.bat\"" ascii //weight: 1
        $x_1_3 = ";copy /b compiler.mpm + config.txt + rebd.7z gallery_mpm.exe;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

