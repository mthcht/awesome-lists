rule PWS_MSIL_OnLineGames_NW_2147717060_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/OnLineGames.NW!bit"
        threat_id = "2147717060"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "OnLineGames"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "\\growtopia\\save.dat" wide //weight: 2
        $x_1_2 = "\\TEMP\\z1.txt" wide //weight: 1
        $x_2_3 = {2e 00 74 00 78 00 74 00 ?? ?? 73 00 6d 00 74 00 70 00 2e 00 ?? ?? 67 00 6d 00 61 00 69 00 6c 00 ?? ?? 2e 00 63 00 6f 00 6d 00}  //weight: 2, accuracy: Low
        $x_1_4 = {5c 50 72 6f 6a 65 63 74 73 5c 43 6f 6e 73 6f 6c 65 41 70 70 6c 69 63 61 74 69 6f 6e [0-2] 5c 43 6f 6e 73 6f 6c 65 41 70 70 6c 69 63 61 74 69 6f 6e [0-2] 5c 6f 62 6a 5c 44 65 62 75 67 5c 43 6f 6e 73 6f 6c 65 41 70 70 6c 69 63 61 74 69 6f 6e [0-2] 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

