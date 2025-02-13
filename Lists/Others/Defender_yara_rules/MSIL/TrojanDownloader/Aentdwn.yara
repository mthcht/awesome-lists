rule TrojanDownloader_MSIL_Aentdwn_A_2147724783_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Aentdwn.A!bit"
        threat_id = "2147724783"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Aentdwn"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 00 72 00 61 00 6e 00 74 00 69 00 66 00 75 00 6e 00 2e 00 74 00 6b 00 2f 00 [0-47] 77 00 69 00 6e 00 69 00 63 00 63 00 2e 00 66 00 69 00 6c 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = "winicc.exe" wide //weight: 1
        $x_1_3 = "PubgHackTool" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Aentdwn_C_2147725153_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Aentdwn.C!bit"
        threat_id = "2147725153"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Aentdwn"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "log.log" wide //weight: 1
        $x_1_2 = {6e 00 6e 00 6a 00 61 00 2e 00 70 00 77 00 2f 00 [0-47] 69 00 6e 00 64 00 65 00 78 00 5f 00 76 00 32 00 2e 00 70 00 68 00 70 00}  //weight: 1, accuracy: Low
        $x_1_3 = "DownloadMaster.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

