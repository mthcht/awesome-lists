rule HackTool_PowerShell_Mimikatz_C_2147728963_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:PowerShell/Mimikatz.C"
        threat_id = "2147728963"
        type = "HackTool"
        platform = "PowerShell: "
        family = "Mimikatz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "202"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = "powershell" wide //weight: 50
        $x_50_2 = {69 00 65 00 78 00 [0-3] 28 00}  //weight: 50, accuracy: Low
        $x_50_3 = "net.webclient" wide //weight: 50
        $x_50_4 = ".downloadstring(" wide //weight: 50
        $x_2_5 = "invoke-mimikittenz" wide //weight: 2
        $x_2_6 = "/mimikittenz/" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_50_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule HackTool_PowerShell_Mimikatz_B_2147734365_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:PowerShell/Mimikatz.B"
        threat_id = "2147734365"
        type = "HackTool"
        platform = "PowerShell: "
        family = "Mimikatz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "202"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = "powershell" wide //weight: 50
        $x_50_2 = {69 00 65 00 78 00 [0-3] 28 00}  //weight: 50, accuracy: Low
        $x_50_3 = "net.webclient" wide //weight: 50
        $x_50_4 = ".downloadstring(" wide //weight: 50
        $x_1_5 = {69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 6d 00 69 00 6d 00 69 00 [0-32] 2e 00 70 00 73 00 31 00}  //weight: 1, accuracy: Low
        $x_1_6 = ");invoke-mimi" wide //weight: 1
        $x_2_7 = ");invoke-mimikat" wide //weight: 2
        $x_2_8 = "invoke-mikat.ps1" wide //weight: 2
        $x_2_9 = "invoke-mikatz.ps1" wide //weight: 2
        $x_2_10 = {69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 6d 00 69 00 6d 00 69 00 6b 00 61 00 74 00 [0-2] 2d 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_50_*) and 2 of ($x_1_*))) or
            ((4 of ($x_50_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule HackTool_PowerShell_Mimikatz_SA_2147927632_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:PowerShell/Mimikatz.SA"
        threat_id = "2147927632"
        type = "HackTool"
        platform = "PowerShell: "
        family = "Mimikatz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "[net.securityprotocoltype]::tls12" wide //weight: 10
        $x_10_2 = "if([system.net.webproxy]::getdefaultproxy().address -ne $null)" wide //weight: 10
        $x_10_3 = "[net.credentialcache]::defaultcredentials;" wide //weight: 10
        $x_1_4 = ".downloadstring(" wide //weight: 1
        $x_1_5 = "webclient" wide //weight: 1
        $x_1_6 = "webrequest" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

