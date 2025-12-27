rule HackTool_Win32_DarkKill_DA_2147956925_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/DarkKill.DA!MTB"
        threat_id = "2147956925"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkKill"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\dark-kill\\x64\\Release\\dark.pdb" ascii //weight: 10
        $x_1_2 = "] process with PID: %u killed successfully" ascii //weight: 1
        $x_1_3 = "] Driver loaded!" ascii //weight: 1
        $x_1_4 = "] Blocking creation of %ws" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

