rule TrojanDownloader_X97M_XlmObfuse_B_2147823877_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:X97M/XlmObfuse.B!DG"
        threat_id = "2147823877"
        type = "TrojanDownloader"
        platform = "X97M: Excel 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "XlmObfuse"
        severity = "Critical"
        info = "DG: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 42 01 61 80 28 00 08 5a ?? ?? ?? ?? ?? ?? 08 5a ?? ?? ?? ?? ?? ?? 08 5a ?? ?? ?? ?? ?? ?? 08 42 01 61 80}  //weight: 1, accuracy: Low
        $x_1_2 = {08 42 01 61 80 20 00 08 44 ?? ?? ?? ?? 08 44 ?? ?? ?? ?? 08 44 ?? ?? ?? ?? 08 42 01 61 80}  //weight: 1, accuracy: Low
        $x_1_3 = {42 02 61 80 28 00 08 5a ?? ?? ?? ?? ?? ?? 08 5a ?? ?? ?? ?? ?? ?? 08 5a}  //weight: 1, accuracy: Low
        $x_1_4 = {42 02 61 80 20 00 08 44 ?? ?? ?? ?? 08 44 ?? ?? ?? ?? 08 44}  //weight: 1, accuracy: Low
        $x_1_5 = {08 42 01 61 80 28 00 08 17 (01|02|03) 00 [0-2] 08 17 (01|02|03) 00 [0-2] 08 17}  //weight: 1, accuracy: Low
        $x_1_6 = {42 02 61 80 28 00 08 17 (01|02|03) 00 [0-2] 08 17 (01|02|03) 00 [0-2] 08 17}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

