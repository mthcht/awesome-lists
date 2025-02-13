rule HackTool_PowerShell_PsCredinject_A_2147730342_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:PowerShell/PsCredinject.A!!PsCredinject.A"
        threat_id = "2147730342"
        type = "HackTool"
        platform = "PowerShell: "
        family = "PsCredinject"
        severity = "High"
        info = "PsCredinject: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Invoke-CredentialInjection" wide //weight: 1
        $x_1_2 = "#Start winlogon.exe as SYSTEM" wide //weight: 1
        $x_1_3 = "$WinLogonProcessId = Create-WinLogonProcess" wide //weight: 1
        $x_1_4 = {24 00 4c 00 6f 00 67 00 6f 00 6e 00 90 00 02 00 04 00 42 00 69 00 74 00 5f 00 42 00 61 00 73 00 65 00 36 00 34 00 20 00 3d 00 20 00 22 00 54 00 56 00 71 00}  //weight: 1, accuracy: High
        $x_1_5 = "$WinLogonProcessId = (Get-Process -Name \"winlogon\")[0].Id" wide //weight: 1
        $x_1_6 = "Invoke-ReflectivePEInjection" wide //weight: 1
        $x_1_7 = "$Pipe.WaitForConnection()" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

