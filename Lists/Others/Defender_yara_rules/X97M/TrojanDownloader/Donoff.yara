rule TrojanDownloader_X97M_Donoff_2147707632_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:X97M/Donoff"
        threat_id = "2147707632"
        type = "TrojanDownloader"
        platform = "X97M: Excel 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "Variabl & Chr(fromArr(i) - LenLen - 4 * LenLen - 3312)" ascii //weight: 5
        $x_5_2 = ".Open \"GE\" + UCase(Chr(TOTO))," ascii //weight: 5
        $x_4_3 = {20 3d 20 41 72 72 61 79 28 ?? ?? (30|2d|39) (30|2d|39) 2c 20 ?? ?? (30|2d|39) (30|2d|39) 2c 20 ?? ?? (30|2d|39) (30|2d|39) 2c 20 ?? ?? (30|2d|39) (30|2d|39) 2c 20 ?? ?? (30|2d|39) (30|2d|39) 2c}  //weight: 4, accuracy: Low
        $x_5_4 = "newYz + \"\\\" + \"coloc\" + LCase(counter) + \"exe\"" ascii //weight: 5
        $x_5_5 = "CreateObject(\"W\" + DB411 + \"cript\" + DB400 + DB411 + \"hell\").Environment(\"Pr\" + LCase(DB403) + \"ce\" + LCase(DB411) + LCase(DB411))" ascii //weight: 5
        $x_5_6 = " + Chr(90 + 2) + \"codakes\" + Chr(50 - 4) + \"exe\"" ascii //weight: 5
        $x_5_7 = "Set Bitmap1 = CreateObject(DB422 + \"icrosoft.\" + DB400 + \"\" + DB422 + \"LH\" + \"\" + \"TTP\")" ascii //weight: 5
        $x_5_8 = "Bitmap1.Open Chr(81 - 10) + \"E\" + UCase(Chr(101 + 10 + 5))," ascii //weight: 5
        $x_7_9 = "CreateObject(UCase(\"m\") + \"icrosof\" + LCase(errorMsg) + \".XMLH\" + errorMsg + errorMsg + \"P\")" ascii //weight: 7
        $x_7_10 = ".Open Chr(Asc(\"H\") - 1) + UCase(arguments) + errorMsg, UtilsAssertToken(homebrew, 45), False" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_4_*))) or
            ((3 of ($x_5_*))) or
            ((1 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_7_*) and 2 of ($x_5_*))) or
            ((2 of ($x_7_*))) or
            (all of ($x*))
        )
}

