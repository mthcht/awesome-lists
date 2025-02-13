rule Backdoor_MacOS_HShell_B_2147810011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/HShell.B!MTB"
        threat_id = "2147810011"
        type = "Backdoor"
        platform = "MacOS: "
        family = "HShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 3b 66 10 76 73 48 83 ec 28 48 89 6c 24 20 48 8d 6c 24 20 48 89 44 24 30 48 89 4c 24 40 66 90 48 83 fb 04 75 08 81 38 68 74 74 70 74 14 48 83 fb 05 75 15 81 38 68 74 74 70 75 0d 80 78 04 73 75 07}  //weight: 1, accuracy: High
        $x_1_2 = "hershell-master/meterpreter/meterpreter.go" ascii //weight: 1
        $x_1_3 = "github.com/sysdream/hershell" ascii //weight: 1
        $x_1_4 = "shell.InjectShellcode" ascii //weight: 1
        $x_1_5 = "hershell/shell.ExecShellcode" ascii //weight: 1
        $x_1_6 = "meterpreter.ReverseTcp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

