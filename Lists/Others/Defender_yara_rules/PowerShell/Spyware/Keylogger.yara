rule Spyware_PowerShell_Keylogger_G_259791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spyware:PowerShell/Keylogger.G!MTB"
        threat_id = "259791"
        type = "Spyware"
        platform = "PowerShell: "
        family = "Keylogger"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KeyLogger" ascii //weight: 1
        $x_10_2 = "\\Mozilla\\Firefox\\Profiles\\" ascii //weight: 10
        $x_1_3 = "Debugger" ascii //weight: 1
        $x_1_4 = "\\logins.json" ascii //weight: 1
        $x_1_5 = "ip-score.com/checkip/" ascii //weight: 1
        $x_1_6 = "Kaspersky" ascii //weight: 1
        $x_1_7 = "ANTIVIRUS" ascii //weight: 1
        $x_10_8 = "powershell.exe -executionpolicy bypass" ascii //weight: 10
        $x_1_9 = "compromised!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

