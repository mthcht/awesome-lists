rule TrojanDropper_W97M_SideTwist_A_2147828390_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:W97M/SideTwist.A"
        threat_id = "2147828390"
        type = "TrojanDropper"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "SideTwist"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "data(Index) = (EncData0 * S2) Or (EncData1 \\ S4)" ascii //weight: 1
        $x_1_2 = "targetSubfolder = \"System\" & \"Failure\" & \"Reporter\"" ascii //weight: 1
        $x_1_3 = "mainTargetPath & bslash & targetSubfolder & bslash & \"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

