rule Virus_X97M_Thus_A_2147691679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:X97M/Thus.gen!A"
        threat_id = "2147691679"
        type = "Virus"
        platform = "X97M: Excel 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Thus"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "'Thus_001'" ascii //weight: 1
        $x_1_2 = "'Anti-Smyser'" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

