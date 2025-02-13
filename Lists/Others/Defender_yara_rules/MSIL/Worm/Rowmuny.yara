rule Worm_MSIL_Rowmuny_A_2147632776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Rowmuny.A"
        threat_id = "2147632776"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rowmuny"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "echo ^<iframe src=" wide //weight: 2
        $x_2_2 = "[autorun]" wide //weight: 2
        $x_2_3 = "For Each KZN In Fruxr.Friends" wide //weight: 2
        $x_1_4 = "height=0 width=0^> >>%" wide //weight: 1
        $x_1_5 = "width=0 height=0^>^</iframe^> >>%" wide //weight: 1
        $x_1_6 = "SELECT * FROM Win32_VideoController" wide //weight: 1
        $x_1_7 = {5c 00 24 00 41 00 44 00 4d 00 49 00 4e 00 5c 00 [0-18] 2e 00 73 00 63 00 72 00}  //weight: 1, accuracy: Low
        $x_1_8 = {5c 00 41 00 64 00 6d 00 69 00 6e 00 24 00 5c 00 [0-18] 2e 00 73 00 63 00 72 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

