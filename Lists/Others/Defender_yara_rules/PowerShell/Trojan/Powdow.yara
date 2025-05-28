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

rule Trojan_PowerShell_Powdow_RK_2147942322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/Powdow.RK!MTB"
        threat_id = "2147942322"
        type = "Trojan"
        platform = "PowerShell: "
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PowerShell" wide //weight: 1
        $x_1_2 = "-EncodedCommand" wide //weight: 1
        $x_1_3 = "-w h -e" wide //weight: 1
        $x_10_4 = "aQBlAHgAKABpAHcAcgAgAC0AVQByAGkAIAAnAGgAdAB0AHAA" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

