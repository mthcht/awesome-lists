rule VirTool_Win32_Reshler_A_2147752783_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Reshler.A"
        threat_id = "2147752783"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Reshler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/hershell/shell.ExecuteCmd" ascii //weight: 1
        $x_1_2 = "/hershell/shell.GetShell" ascii //weight: 1
        $x_1_3 = "/hershell/meterpreter" ascii //weight: 1
        $x_1_4 = "/shell.InjectShellcode" ascii //weight: 1
        $x_1_5 = "/shell.ExecShellcode" ascii //weight: 1
        $x_1_6 = "/meterpreter.generateURIChecksum" ascii //weight: 1
        $x_1_7 = "/meterpreter.reverseTCP" ascii //weight: 1
        $x_1_8 = "/meterpreter.reverseHTTP" ascii //weight: 1
        $x_1_9 = "/shell/shell_windows" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

