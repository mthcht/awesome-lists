rule TrojanDropper_MSIL_AusterePurlin_C_2147975419_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/AusterePurlin.C!dha"
        threat_id = "2147975419"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AusterePurlin"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tvsabp.rkr.rgnqch" ascii //weight: 1
        $x_1_2 = "-erfHxfnGrgnqcHzbbM" ascii //weight: 1
        $x_1_3 = "rgnqch\\avo\\zbbM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

