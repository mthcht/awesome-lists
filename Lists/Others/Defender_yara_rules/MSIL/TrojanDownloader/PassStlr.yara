rule TrojanDownloader_MSIL_PassStlr_SA_2147735259_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/PassStlr.SA"
        threat_id = "2147735259"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PassStlr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_UseSystemPasswordChar" ascii //weight: 1
        $x_1_2 = "\\You Clean PC\\obj\\Debug\\You Clean PC.pdb" ascii //weight: 1
        $x_1_3 = "$2aab27fc-44c3-45d9-ab10-a55166cf202b" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

