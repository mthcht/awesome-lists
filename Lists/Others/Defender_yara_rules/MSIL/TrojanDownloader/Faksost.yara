rule TrojanDownloader_MSIL_Faksost_B_2147722763_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Faksost.B!bit"
        threat_id = "2147722763"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Faksost"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "aHR0cHM6Ly93d3cudXBsb2FkLmVlL2Rvd25sb2FkLzcxOTY4MDkvNzBiNjNjMDk5MGRmMTFlNDVmNGUvU2VydmVyLmV4ZQ==" wide //weight: 3
        $x_1_2 = "dGVtcA==" wide //weight: 1
        $x_2_3 = "L3NlcnZlci5leGU=" wide //weight: 2
        $x_3_4 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 75 70 6c 6f 61 64 2e 65 65 2f [0-54] 2f 53 65 72 76 65 72 2e 65 78 65}  //weight: 3, accuracy: Low
        $x_1_5 = "/server.exe" ascii //weight: 1
        $x_1_6 = "DownloadFile" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

