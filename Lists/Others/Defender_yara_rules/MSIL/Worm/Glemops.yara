rule Worm_MSIL_Glemops_A_2147650198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Glemops.gen!A"
        threat_id = "2147650198"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Glemops"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sKey SE ByIshtar" wide //weight: 1
        $x_1_2 = "Nom de la victime" wide //weight: 1
        $x_1_3 = "dllcache\\myporn.scr" wide //weight: 1
        $x_1_4 = "Hadeskey SE : Stealer (FireFox)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

