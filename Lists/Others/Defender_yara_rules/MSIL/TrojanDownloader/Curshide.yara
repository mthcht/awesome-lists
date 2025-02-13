rule TrojanDownloader_MSIL_Curshide_A_2147729510_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Curshide.A!bit"
        threat_id = "2147729510"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Curshide"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "netsh advfirewall set allprofiles state" wide //weight: 1
        $x_1_2 = "Server = cannotjavac.com; Database = cannotjavac_com_PTE;" wide //weight: 1
        $x_1_3 = "http://cannotjavac.com/pte/linkwindowscrush.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

