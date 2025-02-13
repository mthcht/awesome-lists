rule Backdoor_Linux_HShell_A_2147810010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/HShell.A!MTB"
        threat_id = "2147810010"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "HShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/hershell/shell.InjectShellcode" ascii //weight: 1
        $x_1_2 = "meterpreter.ReverseHttp" ascii //weight: 1
        $x_1_3 = "hershell-master/meterpreter/meterpreter.go" ascii //weight: 1
        $x_1_4 = "sysdream/hershell/shell.GetShell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

