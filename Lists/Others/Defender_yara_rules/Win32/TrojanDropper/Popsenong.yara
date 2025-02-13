rule TrojanDropper_Win32_Popsenong_A_2147640550_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Popsenong.A"
        threat_id = "2147640550"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Popsenong"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 00 3a 00 5c 00 73 00 68 00 65 00 6e 00 6c 00 6f 00 6e 00 67 00 5c 00 27 59 a2 5b 37 62 5c 00 [0-32] 56 00 42 00 ea 81 2f 54 a8 52 5c 00 ca 91 3e 65 ef 7a 5c 00 e5 5d 0b 7a 31 00 2e 00 76 00 62 00 70}  //weight: 1, accuracy: Low
        $x_1_2 = {4d 6f 64 44 65 6c 65 74 65 4d 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

