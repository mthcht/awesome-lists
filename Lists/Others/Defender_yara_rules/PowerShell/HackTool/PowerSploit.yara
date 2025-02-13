rule HackTool_PowerShell_PowerSploit_A_2147734715_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:PowerShell/PowerSploit.A"
        threat_id = "2147734715"
        type = "HackTool"
        platform = "PowerShell: "
        family = "PowerSploit"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "202"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = "powershell" wide //weight: 50
        $x_50_2 = {69 00 65 00 78 00 [0-3] 28 00}  //weight: 50, accuracy: Low
        $x_50_3 = "net.webclient" wide //weight: 50
        $x_50_4 = ".downloadstring(" wide //weight: 50
        $x_2_5 = "/powersploit/raw/master/exfiltration/" wide //weight: 2
        $x_2_6 = "/get-gppautologon.ps1" wide //weight: 2
        $x_2_7 = "/get-gpppassword.ps1" wide //weight: 2
        $x_2_8 = "/get-keystrokes.ps1" wide //weight: 2
        $x_2_9 = "/get-microphoneaudio.ps1" wide //weight: 2
        $x_2_10 = "/get-timedscreenshot.ps1" wide //weight: 2
        $x_2_11 = "/invoke-credentialinjection.ps1" wide //weight: 2
        $x_2_12 = "/invoke-ninjacopy.ps1" wide //weight: 2
        $x_2_13 = "/invoke-tokenmanipulation.ps1" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_50_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

