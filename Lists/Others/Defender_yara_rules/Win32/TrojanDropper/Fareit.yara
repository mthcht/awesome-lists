rule TrojanDropper_Win32_Fareit_2147708656_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Fareit"
        threat_id = "2147708656"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\"/Au\" & \"toI\" & \"t3Ex\" & \"ecu\" & \"teSc\" & \"ript \" & @TEMPDIR & \"\\\" & \"lol\" & \".bi\" & \"n\"" wide //weight: 1
        $x_1_2 = {53 00 48 00 45 00 4c 00 4c 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 40 00 53 00 43 00 52 00 49 00 50 00 54 00 46 00 55 00 4c 00 4c 00 50 00 41 00 54 00 48 00 20 00 2c 00 20 00 24 00 [0-16] 20 00 2c 00 20 00 40 00 53 00 43 00 52 00 49 00 50 00 54 00 44 00 49 00 52 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_3 = "FILEWRITE ( FILEOPEN ( @TEMPDIR & \"\\lol\" & \".bi\" & \"n\"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

