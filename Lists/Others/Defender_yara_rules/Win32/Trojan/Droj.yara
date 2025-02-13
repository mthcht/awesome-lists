rule Trojan_Win32_Droj_A_2147683780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Droj.A"
        threat_id = "2147683780"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Droj"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "<$*&-@-&*$>" wide //weight: 1
        $x_1_2 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 52 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 54 00 6f 00 6f 00 6c 00 73 00 [0-10] 44 00 69 00 73 00 61 00 62 00 6c 00 65 00 54 00 61 00 73 00 6b 00 4d 00 67 00 72 00 [0-10] 6e 00 65 00 74 00 73 00 68 00 20 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 20 00 61 00 64 00 64 00 20 00 61 00 6c 00 6c 00 6f 00 77 00 65 00 64 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00}  //weight: 1, accuracy: Low
        $x_1_3 = "Made By Dr.Trojan" ascii //weight: 1
        $x_1_4 = {48 00 69 00 64 00 65 00 46 00 69 00 6c 00 65 00 45 00 78 00 74 00 [0-10] 53 00 75 00 70 00 65 00 72 00 48 00 69 00 64 00 64 00 65 00 6e 00 [0-10] 53 00 68 00 6f 00 77 00 53 00 75 00 70 00 65 00 72 00 48 00 69 00 64 00 64 00 65 00 6e 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

