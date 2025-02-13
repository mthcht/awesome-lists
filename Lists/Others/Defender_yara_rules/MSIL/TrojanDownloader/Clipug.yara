rule TrojanDownloader_MSIL_Clipug_A_2147688534_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Clipug.A"
        threat_id = "2147688534"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Clipug"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VB Z neta\\WindowsApplication1\\WindowsApplication1\\obj\\x86\\Debug\\WindowsApplication1.pdb" ascii //weight: 1
        $x_1_2 = "http://sluzby-specjalne.cba.pl/nr26.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

