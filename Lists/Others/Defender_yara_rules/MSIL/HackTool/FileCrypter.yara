rule HackTool_MSIL_FileCrypter_SX_2147972442_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/FileCrypter.SX!MTB"
        threat_id = "2147972442"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCrypter"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "FUD CRYPTER v2.0 - SECO" ascii //weight: 30
        $x_20_2 = "[*] Compiling stub..." ascii //weight: 20
        $x_5_3 = "Usage: SecoCrypter.exe <input_file> <output_file>" ascii //weight: 5
        $x_5_4 = "CRYPTING COMPLETE!" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

