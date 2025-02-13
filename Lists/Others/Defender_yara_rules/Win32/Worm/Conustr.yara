rule Worm_Win32_Conustr_A_2147685097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Conustr.A"
        threat_id = "2147685097"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Conustr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ppxxxx" wide //weight: 1
        $x_1_2 = "T9[QDBXBKDQ[Cbekx-dwd" wide //weight: 1
        $x_1_3 = {56 f7 d1 2b f9 6a 02 8b d1 8b f7 8b f8 c1 e9 02 f3 a5 8b ca 83 e1 03}  //weight: 1, accuracy: High
        $x_1_4 = {80 3e 63 74 4a 80 fb 02 75 1c 8d 54 24 10 c6 06 01 52 e8 ?? 00 00 00 83 c4 04 f7 d8 1a c0 24 64 fe c8 88 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

