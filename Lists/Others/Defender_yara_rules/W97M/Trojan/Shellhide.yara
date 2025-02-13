rule Trojan_W97M_Shellhide_A_2147691658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:W97M/Shellhide.gen!A"
        threat_id = "2147691658"
        type = "Trojan"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Shellhide"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub Auto_Open()" ascii //weight: 1
        $x_1_2 = {53 68 65 6c 6c 28 43 68 72 6f 6d 65 [0-2] 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
        $x_1_3 = "Environ(\"USERPROFILE\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

