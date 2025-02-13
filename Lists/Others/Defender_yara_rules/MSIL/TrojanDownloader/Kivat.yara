rule TrojanDownloader_MSIL_Kivat_A_2147688209_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Kivat.A"
        threat_id = "2147688209"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kivat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bgas.txt" ascii //weight: 1
        $x_1_2 = "jsas.txt" ascii //weight: 1
        $x_2_3 = "\\iacffndadciecdcopofkkegcpcmnjpph\\" ascii //weight: 2
        $x_1_4 = {47 f6 72 65 76 20 59 f6 6e 65 74 69 63 69 73 69 20 2d 20 47 6f 6f 67 6c 65 20 43 68 72 6f 6d 65}  //weight: 1, accuracy: High
        $x_2_5 = "winupdater.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Kivat_B_2147688509_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Kivat.B"
        threat_id = "2147688509"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kivat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bgqm.txt" ascii //weight: 1
        $x_1_2 = "jsxmq.txt" ascii //weight: 1
        $x_2_3 = "\\iacffndadciecdcopofkkegcpcmnjpph\\" ascii //weight: 2
        $x_1_4 = {47 f6 72 65 76 20 59 f6 6e 65 74 69 63 69 73 69 20 2d 20 47 6f 6f 67 6c 65 20 43 68 72 6f 6d 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

