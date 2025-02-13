rule Trojan_Win32_Gakivod_A_2147649355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gakivod.A"
        threat_id = "2147649355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gakivod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {7c ed 8b c6 2b c1 2b c2 2b 45 fc 53 83 e8 3d 99 2b c2 8b f8 d1 ff 33 db 8b f3 69 f6 18 02 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {8b 4d 10 8b 01 3b c2 76 05 83 f8 2f 76 0c 83 f8 60 72 16}  //weight: 2, accuracy: High
        $x_2_3 = {48 74 3a 83 e8 0e 74 2b 2d 02 01 00 00 75 37 8b 45 10 c1 e8 10 74 15 3d 00 03 00 00}  //weight: 2, accuracy: High
        $x_1_4 = "%s%s%d.jpg" wide //weight: 1
        $x_1_5 = "gdilog.log" wide //weight: 1
        $x_1_6 = "2C508BD5-F9C6-4955-B93A-09B835EC3C64" wide //weight: 1
        $x_1_7 = "0105A438-B9CC-4a29-89B1-DA194DFA4B40" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

