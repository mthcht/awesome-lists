rule Worm_Win32_Threxmond_A_2147610305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Threxmond.A"
        threat_id = "2147610305"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Threxmond"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\Base de donnee\\test\\Projet1.vbp" wide //weight: 1
        $x_3_2 = {00 6b 00 3a 00 5c 00 33 00 78 00 58 00 78 00 33 00 ?? ?? 2e 00 65 00 78 00 65 00 00}  //weight: 3, accuracy: Low
        $x_1_3 = {00 00 5b 00 41 00 75 00 74 00 6f 00 72 00 75 00 6e 00 5d 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "funcopy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

