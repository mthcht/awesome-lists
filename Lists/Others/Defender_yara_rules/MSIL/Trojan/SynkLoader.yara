rule Trojan_MSIL_SynkLoader_MR_2147977264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SynkLoader.MR!MTB"
        threat_id = "2147977264"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SynkLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "source\\repos\\pwsldll\\x64\\Release\\pwsldll.pdb" ascii //weight: 2
        $x_1_2 = "InitializePowerShell" ascii //weight: 1
        $x_1_3 = "ExecutePowerShellCommand" ascii //weight: 1
        $x_1_4 = "ExecutePowerShellScript" ascii //weight: 1
        $x_1_5 = "pwsldll.dll" ascii //weight: 1
        $x_1_6 = "Exception reading script:" ascii //weight: 1
        $x_1_7 = "System.Management.Automation" ascii //weight: 1
        $x_1_8 = "Command executed (no output)" ascii //weight: 1
        $x_1_9 = "PSDataCollection" ascii //weight: 1
        $x_1_10 = "ReadAllText" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

