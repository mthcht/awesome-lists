rule TrojanDownloader_O97M_XlmMacro_DG_2147793012_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/XlmMacro.gen!DG"
        threat_id = "2147793012"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "XlmMacro"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 6f 00 08}  //weight: 1, accuracy: High
        $x_1_2 = {41 6f 00 03}  //weight: 1, accuracy: High
        $x_1_3 = {41 6f 00 04}  //weight: 1, accuracy: High
        $x_1_4 = {42 01 06 80}  //weight: 1, accuracy: High
        $x_1_5 = {42 02 60 80}  //weight: 1, accuracy: High
        $x_1_6 = {42 01 60 80}  //weight: 1, accuracy: High
        $x_1_7 = {42 01 11 80}  //weight: 1, accuracy: High
        $x_1_8 = {42 01 6e 00}  //weight: 1, accuracy: High
        $x_1_9 = {42 07 95 00}  //weight: 1, accuracy: High
        $x_1_10 = {42 06 96 00}  //weight: 1, accuracy: High
        $x_1_11 = {42 07 96 00}  //weight: 1, accuracy: High
        $x_1_12 = {42 08 96 00}  //weight: 1, accuracy: High
        $x_1_13 = {42 09 96 00}  //weight: 1, accuracy: High
        $x_1_14 = {08 41 01 01}  //weight: 1, accuracy: High
        $x_1_15 = {08 17 01 00 [0-3] 00 08 17 01 00 [0-3] 00 08 17 01 00 20 00 00 00 17 01 00 [0-3] 00 17 01 00 [0-3] 00}  //weight: 1, accuracy: Low
        $x_1_16 = {42 01 50 01}  //weight: 1, accuracy: High
        $x_1_17 = {42 02 50 01}  //weight: 1, accuracy: High
        $x_1_18 = {42 03 50 01}  //weight: 1, accuracy: High
        $x_1_19 = {42 04 50 01}  //weight: 1, accuracy: High
        $x_1_20 = {42 05 50 01}  //weight: 1, accuracy: High
        $x_1_21 = {42 06 50 01}  //weight: 1, accuracy: High
        $x_1_22 = {42 07 50 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

