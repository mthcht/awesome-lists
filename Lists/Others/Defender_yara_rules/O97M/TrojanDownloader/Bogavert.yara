rule TrojanDownloader_O97M_Bogavert_A_2147686578_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bogavert.A"
        threat_id = "2147686578"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bogavert"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= CreateObject(\"MSXML2.XMLHTTP\")" ascii //weight: 1
        $x_1_2 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_3 = ".Send \"send request" ascii //weight: 1
        $x_1_4 = {44 6f 20 57 68 69 6c 65 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 72 65 61 64 79 53 74 61 74 65 20 3c ?? 20 (31|2d|39)}  //weight: 1, accuracy: Low
        $x_1_5 = {4f 70 65 6e 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 20 46 6f 72 20 42 69 6e 61 72 79 20 41 73 20 23}  //weight: 1, accuracy: Low
        $x_1_6 = {3d 20 53 68 65 6c 6c 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2c 20 31 29}  //weight: 1, accuracy: Low
        $x_1_7 = "Environ(\"USERPROFILE\") &" ascii //weight: 1
        $x_1_8 = "Environ(\"AppData\") &" ascii //weight: 1
        $x_1_9 = "= CreateObject(StrReverse(Hex2Str(\"505454484C4D582E324C4D58534D\")" ascii //weight: 1
        $x_1_10 = {2e 4f 70 65 6e 20 53 74 72 52 65 76 65 72 73 65 28 48 65 78 32 53 74 72 28 22 35 34 34 35 34 37 22 29 29 2c 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_11 = ".Send StrReverse(Hex2Str(\"7473657571657220646E6573\")" ascii //weight: 1
        $x_1_12 = "Environ(StrReverse(Hex2Str(\"656C69666F725072657355\"))) &" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

