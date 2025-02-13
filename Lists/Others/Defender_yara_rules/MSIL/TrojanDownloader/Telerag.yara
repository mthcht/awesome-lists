rule TrojanDownloader_MSIL_Telerag_A_2147729930_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Telerag.A!bit"
        threat_id = "2147729930"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Telerag"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://telegra.ph/" wide //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = "\\CoLoader\\obj\\Release\\CoLoader.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

