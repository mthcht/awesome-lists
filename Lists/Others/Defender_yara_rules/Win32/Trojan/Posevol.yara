rule Trojan_Win32_Posevol_A_2147695376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Posevol.A"
        threat_id = "2147695376"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Posevol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {75 ef 8a 19 33 d2 84 db 74 16 8d 75 bc 2b f1 b0 20 2a c2 32 c3 42 88 04 0e 41}  //weight: 1, accuracy: High
        $x_1_2 = {75 ee 3b 5d fc 74 0e 8b 4d f4 42 3b 55 f8 76 d6 83 c8 ff eb 0f}  //weight: 1, accuracy: High
        $x_1_3 = {c7 44 30 ff 3a 64 65 66 c7 44 30 03 72 61 67 2e c7 44 30 07 76 62 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {75 48 39 5d 0c 74 32 81 7d f8 80 00 00 00 77 29 8d 45 f8 ba 34 b4 d7 6a}  //weight: 1, accuracy: High
        $x_1_5 = {36 31 33 66 65 30 34 30 35 33 63 61 34 65 30 35 61 30 35 39 30 34 34 30 62 39 38 62 32 65 35 39 00}  //weight: 1, accuracy: High
        $x_1_6 = {48 57 41 57 41 57 41 57 41 0a 25 73 0a 25 73 0a 25 63}  //weight: 1, accuracy: High
        $x_1_7 = "%TMP%:Defrag.scr" ascii //weight: 1
        $x_1_8 = "derpos/gateway.php" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

