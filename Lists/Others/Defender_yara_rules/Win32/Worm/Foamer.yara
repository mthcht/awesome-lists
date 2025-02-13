rule Worm_Win32_Foamer_A_2147597918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Foamer.A"
        threat_id = "2147597918"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Foamer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {47 00 65 00 74 00 44 00 72 00 69 00 76 00 65 00 00 00 00 00 49 00 73 00 52 00 65 00 61 00 64 00 79 00 00 00 1a 00 00 00 3a 00 5c 00 6d 00 6f 00 61 00 70 00 68 00 69 00 65 00 2e 00 65 00 78 00 65 00 00 00 1a 00 00 00 3a 00 5c 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00}  //weight: 1, accuracy: High
        $x_1_2 = "\\Program Files\\Microsoft SQL Server\\80\\Tools\\Bi" wide //weight: 1
        $x_1_3 = "MOAPHIE THE MONALISA CREATED BY MOAPHIE" wide //weight: 1
        $x_1_4 = "cls && echo THE WORLD-WIDE DONT ACCEPT COMMAND PROMPT!!!! && exit" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

