rule Trojan_PowerShell_Powdow_AMS_2147764991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/Powdow.AMS!MTB"
        threat_id = "2147764991"
        type = "Trojan"
        platform = "PowerShell: "
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Powershell -Windowstyle Hidden -encodedCommand dwBnAGUAdAAgAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgA2AC8AcABvAHcAZQByAHMAaABlAGwAbAAuAHAAcwAxACAALQBPAHUAdABGAGkAbABlACAAQwA6AFwAVQBzAGUAc" ascii //weight: 1
        $x_1_2 = "objShell.Run (\"powershell.exe -encodedCommand LQBFAHgAZQBjAHUAdABpAG8AbgBQAG8AbABpAGMAeQAgAEIAeQBwAGEAcwBzACA" ascii //weight: 1
        $x_1_3 = " = WshShellExec.StdOut.ReadAll" ascii //weight: 1
        $x_1_4 = "Sub RunAndGetCmd()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

