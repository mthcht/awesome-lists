rule Worm_Win32_Recspa_A_2147613236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Recspa.A"
        threat_id = "2147613236"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Recspa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {3a c4 fe 12 00 fb ef 64 fe 60 31 24 ff 36 06 00 84 fe 74 fe 64 fe 00 0f 6c 24 ff 04 14 ff 55 f4 ff fe 5d 20 00 00 56 04 14 ff 55 1b 13 00 1b 14 00 2a 23 04 ff 1b 15 00 2a}  //weight: 2, accuracy: High
        $x_2_2 = {3a 50 ff 37 00 5d fb 33 35 40 ff 1c 7f 01 08 08 00 06 34 00 4d 60 ff 03 40 0a 38 00 04 00 6c 78 ff 1b 39 00 fb 30 1c 9d 01 3a}  //weight: 2, accuracy: High
        $x_1_3 = "[Autorun]" wide //weight: 1
        $x_1_4 = "Espiar" wide //weight: 1
        $x_1_5 = "Envio de imagen completo" wide //weight: 1
        $x_1_6 = "Recibir Unidades" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

