rule HackTool_MSIL_Mkatzloader_MA_2147809053_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Mkatzloader.MA!MTB"
        threat_id = "2147809053"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mkatzloader"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PELoader" ascii //weight: 1
        $x_1_2 = "KatzCompressed" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "Decompress" ascii //weight: 1
        $x_1_5 = "Preferred Load Address = {0}" wide //weight: 1
        $x_1_6 = "Allocated Space For {0} at {1}" wide //weight: 1
        $x_1_7 = "Section {0}, Copied To {1}" wide //weight: 1
        $x_1_8 = "Delta = {0}A" wide //weight: 1
        $x_1_9 = "Loaded {0}" wide //weight: 1
        $x_10_10 = "Executing Mimikatz" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

