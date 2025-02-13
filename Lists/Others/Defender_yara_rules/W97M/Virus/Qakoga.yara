rule Virus_W97M_Qakoga_A_2147724786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:W97M/Qakoga.A"
        threat_id = "2147724786"
        type = "Virus"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Qakoga"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "+ \"tectedView\", \"DisableAtt\" + \"achementsInPV\")" ascii //weight: 1
        $x_1_2 = "+ \"kcontentexec\" + \"utionfro\" + \"minte\" + \"rnet\")" ascii //weight: 1
        $x_1_3 = "InfectedAD = (AD.Name = \"qkG\")" ascii //weight: 1
        $x_1_4 = "AD.CodeModule.AddFromString (\"Private Sub Document_Open()\")" ascii //weight: 1
        $x_1_5 = "NT.CodeModule.AddFromString (\"Private Sub Document_Close()\")" ascii //weight: 1
        $x_1_6 = "Crypto = byOut" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

