rule Worm_Win32_Seefiak_A_2147652040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Seefiak.A"
        threat_id = "2147652040"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Seefiak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "funciones.php?nick=" wide //weight: 5
        $x_1_2 = "Adios Admin!" wide //weight: 1
        $x_1_3 = "El spread face ya esta activado" wide //weight: 1
        $x_1_4 = "spread.msn.false" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Seefiak_A_2147652040_1
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Seefiak.A"
        threat_id = "2147652040"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Seefiak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {75 00 66 00 63 00 6e 00 6f 00 69 00 65 00 6e 00 2e 00 73 00 68 00 70 00 3f 00 70 00 69 00 6e 00 6b 00 63 00 00 00 3d 00}  //weight: 5, accuracy: High
        $x_1_2 = "dAoi sdAim!n" wide //weight: 1
        $x_1_3 = "lEs rpae dsm naye ts acaitavod" wide //weight: 1
        $x_1_4 = "pserdam.nsf.laes" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

