rule Virus_Win32_Zori_A_2147512351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Zori.A"
        threat_id = "2147512351"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Zori"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 64 69 72 2e 7a 69 70 00 00 00 00 ff ff ff ff 0b 00 00 00 44 6f 77 6e 4c 6f 61 64 44 69 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 73 76 63 68 6f 73 74 2e 64 6c 6c 00 00 00 00 ff ff ff ff 0c 00 00 00 77 69 6e 6c 6f 67 6f 6e}  //weight: 1, accuracy: High
        $x_1_3 = {b9 a4 d7 f7 d7 e9 a3 ba 20 20 20 20 20 20 20 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

