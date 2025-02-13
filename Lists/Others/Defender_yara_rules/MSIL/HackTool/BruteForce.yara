rule HackTool_MSIL_BruteForce_G_2147756503_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/BruteForce.G!MSR"
        threat_id = "2147756503"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BruteForce"
        severity = "High"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Windows_8._1_Activator.Splash.resources" ascii //weight: 3
        $x_2_2 = "PublicKeyToken=b77a5c561934e089" ascii //weight: 2
        $x_1_3 = "PublicKeyToken=b03f5f7f11d50a3a" ascii //weight: 1
        $x_2_4 = "KMS Activator" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MSIL_BruteForce_ARA_2147915620_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/BruteForce.ARA!MTB"
        threat_id = "2147915620"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BruteForce"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "GeneratePassword" ascii //weight: 2
        $x_2_2 = "BruteRunner" ascii //weight: 2
        $x_2_3 = "ConvertToBase64" ascii //weight: 2
        $x_1_4 = "mails.txt" wide //weight: 1
        $x_1_5 = "Proxies.txt" wide //weight: 1
        $x_1_6 = "Remaining Combo.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

