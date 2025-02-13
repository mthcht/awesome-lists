rule TrojanDownloader_O97M_MacroConstructor_2147794403_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/MacroConstructor"
        threat_id = "2147794403"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "MacroConstructor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {3d 65 78 63 65 6c 34 6d 61 63 72 6f 73 68 65 65 74 73 20 00 73 65 74}  //weight: 10, accuracy: Low
        $x_10_2 = {3d 65 78 63 65 6c 34 69 6e 74 6c 6d 61 63 72 6f 73 68 65 65 74 73 20 00 73 65 74}  //weight: 10, accuracy: Low
        $x_10_3 = "excel4macrosheets.add(" ascii //weight: 10
        $x_10_4 = "excel4intlmacrosheets.add(" ascii //weight: 10
        $x_10_5 = "application.runsheets(" ascii //weight: 10
        $x_10_6 = "run(\"\"&" ascii //weight: 10
        $x_1_7 = ".formulalocal=" ascii //weight: 1
        $x_1_8 = "=\"=exec(" ascii //weight: 1
        $x_1_9 = "=\"=execute(" ascii //weight: 1
        $x_1_10 = "=\"=register(" ascii //weight: 1
        $x_1_11 = "=\"=halt()" ascii //weight: 1
        $x_1_12 = "=\"=concatenate(" ascii //weight: 1
        $x_1_13 = "=\"=call(" ascii //weight: 1
        $x_1_14 = "=\"=run(" ascii //weight: 1
        $x_1_15 = "=\"=formula(" ascii //weight: 1
        $x_1_16 = "=\"=fwrite(" ascii //weight: 1
        $x_1_17 = "=\"=file.delete(" ascii //weight: 1
        $x_1_18 = "=\"=set.value(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 11 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

