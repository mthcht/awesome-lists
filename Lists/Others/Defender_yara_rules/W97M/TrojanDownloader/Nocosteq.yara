rule TrojanDownloader_W97M_Nocosteq_A_2147688342_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Nocosteq.A"
        threat_id = "2147688342"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Nocosteq"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 61 6c 6c 20 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 22 68 74 74 70 3a 2f 2f [0-53] 2e 65 78 65 22 2c 20 22 [0-16] 2e 65 78 65 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {43 61 6c 6c 20 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 53 74 72 52 65 76 65 72 73 65 28 22 65 78 65 2e [0-53] 2f 2f 3a 70 74 74 68 22 29 2c 20 22 [0-16] 2e 65 78 65 22 29}  //weight: 1, accuracy: Low
        $x_2_3 = "RunAfterDownload As Boolean = True, Optional RunHide As Boolean = False)" ascii //weight: 2
        $x_2_4 = "MsgBox \"Este documento no es compatible con este equipo.\" & vbCrLf & vbCrLf & \"Por favor intente desde otro equipo.\", vbCritical, \"Error\"" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_W97M_Nocosteq_B_2147693276_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Nocosteq.B"
        threat_id = "2147693276"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Nocosteq"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set SGETSA = CreateObject(\"Microsoft.XMLHTTP\")" ascii //weight: 1
        $x_1_2 = "Set SPOSTSA = CreateObject(\"ADODB.Stream\")" ascii //weight: 1
        $x_1_3 = "Call Shell(FullSavePath, vbNormalFocus)" ascii //weight: 1
        $x_1_4 = "MsgBox \"Este documento no es compatible con este equipo." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

