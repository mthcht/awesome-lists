rule HackTool_PowerShell_CredentialTool_A_2147734714_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:PowerShell/CredentialTool.A"
        threat_id = "2147734714"
        type = "HackTool"
        platform = "PowerShell: "
        family = "CredentialTool"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "202"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = "powershell" wide //weight: 50
        $x_50_2 = {69 00 65 00 78 00 [0-3] 28 00}  //weight: 50, accuracy: Low
        $x_50_3 = "net.webclient" wide //weight: 50
        $x_50_4 = ".downloadstring(" wide //weight: 50
        $x_2_5 = "invoke-wcmdump" wide //weight: 2
        $x_2_6 = "get-vaultcredential.ps1" wide //weight: 2
        $x_1_7 = "/nishang/" wide //weight: 1
        $x_1_8 = "get-webcredentials" wide //weight: 1
        $x_1_9 = "get-lsasecret" wide //weight: 1
        $x_1_10 = "get-passhashes" wide //weight: 1
        $x_1_11 = "get-wlan-keys" wide //weight: 1
        $x_1_12 = "invoke-credentialsphish" wide //weight: 1
        $x_1_13 = "invoke-sessiongopher" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_50_*) and 2 of ($x_1_*))) or
            ((4 of ($x_50_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

