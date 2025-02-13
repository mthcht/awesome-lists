rule Worm_Win32_Busifom_A_2147639128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Busifom.A"
        threat_id = "2147639128"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Busifom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MiBot" wide //weight: 1
        $x_1_2 = "&usu=" wide //weight: 1
        $x_1_3 = "&inf=" wide //weight: 1
        $x_1_4 = "&newly=" wide //weight: 1
        $x_1_5 = ".killp" wide //weight: 1
        $x_1_6 = ".downif" wide //weight: 1
        $x_1_7 = ".bye4ever" wide //weight: 1
        $x_1_8 = "<-#SUBIDOS#->" wide //weight: 1
        $x_1_9 = "[AUTORUn]" wide //weight: 1
        $x_1_10 = "?gStealer" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

