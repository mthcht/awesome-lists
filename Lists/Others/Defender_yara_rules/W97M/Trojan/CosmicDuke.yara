rule Trojan_W97M_CosmicDuke_A_2147690900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:W97M/CosmicDuke.A"
        threat_id = "2147690900"
        type = "Trojan"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "CosmicDuke"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LoadLibrary LibLocation & \"input64.dll\"" ascii //weight: 1
        $x_1_2 = "TempLocation = Environ(\"temp\")" ascii //weight: 1
        $x_1_3 = "input64.dll\" Alias \"exFunc\" ()" ascii //weight: 1
        $x_1_4 = "UnzipSelf((TempLocation))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

