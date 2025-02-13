rule TrojanDownloader_MSIL_Liktad_A_2147697314_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Liktad.A"
        threat_id = "2147697314"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Liktad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 28 13 00 00 06 6f 1e 00 00 0a 0a 28 1f 00 00 0a 06 6f 20 00 00 0a 6f 21 00 00 0a 14 14 6f 22 00 00 0a 26 07 2a}  //weight: 2, accuracy: High
        $x_2_2 = {64 6f 77 6e 69 74 00 77 62 63 00 67 65 74 75 72 6c 00}  //weight: 2, accuracy: High
        $x_1_3 = "/tt.eg//:ptth" wide //weight: 1
        $x_1_4 = "/ten.tsohgr//:ptth" wide //weight: 1
        $x_1_5 = "/moc.erifaidem.www//:ptth" wide //weight: 1
        $x_1_6 = "9009:moc.swanozama.etupmoc.1-tsew-ue.511-321-551-45-2ce//:ptth" wide //weight: 1
        $x_1_7 = "/moc.daolpuelifagem.www//:ptth" wide //weight: 1
        $x_1_8 = {2f 00 74 00 65 00 6e 00 2e 00 64 00 6e 00 65 00 73 00 66 00 2e 00 [0-4] 2f 00 2f 00 3a 00 70 00 74 00 74 00 68 00}  //weight: 1, accuracy: Low
        $x_1_9 = {2f 00 6d 00 6f 00 63 00 2e 00 65 00 72 00 69 00 66 00 61 00 69 00 64 00 65 00 6d 00 2e 00 [0-48] 2f 00 2f 00 3a 00 70 00 74 00 74 00 68 00}  //weight: 1, accuracy: Low
        $x_1_10 = "/moc.puflug.www//:ptth" wide //weight: 1
        $x_1_11 = "/moc.tsohelifatad.www//:ptth" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

