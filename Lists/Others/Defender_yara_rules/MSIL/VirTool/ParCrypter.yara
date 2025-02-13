rule VirTool_MSIL_ParCrypter_A_2147695691_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/ParCrypter.A"
        threat_id = "2147695691"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ParCrypter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Coded for ParCrypter" wide //weight: 1
        $x_1_2 = "\\.\\VBoxMiniRdrDN" wide //weight: 1
        $x_1_3 = "127.0.0.1  virustotal.com" wide //weight: 1
        $x_1_4 = ":Zone.Identifier" wide //weight: 1
        $x_1_5 = "{1},explorer.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

