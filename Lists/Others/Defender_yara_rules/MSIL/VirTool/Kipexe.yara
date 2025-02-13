rule VirTool_MSIL_Kipexe_A_2147696989_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Kipexe.A"
        threat_id = "2147696989"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kipexe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 00 50 00 50 00 44 00 41 00 54 00 41 00 ?? ?? 5c 00 62 00 69 00 6e 00 5c 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 2e 00 65 00 78 00 65 00 ?? ?? 73 00 65 00 72 00 76 00 69 00 63 00 65 00 ?? ?? 63 00 72 00 73 00 73 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = "persistence.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

