rule TrojanDownloader_MSIL_VB_C_2147684582_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/VB.C"
        threat_id = "2147684582"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Instalador do Adobe Flash Player" wide //weight: 2
        $x_3_2 = "\\Adobe Flash Player.pdb" ascii //weight: 3
        $x_3_3 = "744; 311" wide //weight: 3
        $x_4_4 = "Adobe_Flash_Player.Form1.resources" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

