rule VirTool_Win32_Kerbrute_A_2147797321_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Kerbrute.A!MTB"
        threat_id = "2147797321"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Kerbrute"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.bruteForceCombos" ascii //weight: 1
        $x_1_2 = "cmd.passwordSpray" ascii //weight: 1
        $x_1_3 = "cmd.makeBruteWorker" ascii //weight: 1
        $x_1_4 = "session.KerbruteSession.DumpASRepHash" ascii //weight: 1
        $x_1_5 = "session.NewKerbruteSession" ascii //weight: 1
        $x_1_6 = "session.buildKrb5Template" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

