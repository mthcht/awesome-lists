rule Worm_MSIL_Silly_P2P_B_2147642211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Silly_P2P.B"
        threat_id = "2147642211"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Silly_P2P"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\\redlof derahs ym\\++k etil aazak\\" wide //weight: 3
        $x_3_2 = "\\redlof derahs ym\\suehprom\\" wide //weight: 3
        $x_1_3 = "SteamHack.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

