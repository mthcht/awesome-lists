rule Trojan_Win32_Chanitor_A_2147689277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chanitor.A"
        threat_id = "2147689277"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chanitor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b0 20 2a c2 32 c3 42 88 04 0e 41 8a 19 84 db 75}  //weight: 1, accuracy: High
        $x_1_2 = {8d 0c 3a b0 12 2a c2 32 04 0b 42 88 01 3b d6 72}  //weight: 1, accuracy: High
        $x_1_3 = "Kzlsyw)+" ascii //weight: 1
        $x_1_4 = {3c 65 7f 7d 3c 7a 69 69 24 66 7a 60}  //weight: 1, accuracy: High
        $x_1_5 = {ed e9 9d eb ef 9b ef ee f8 e3 e2 96 e2 fd fb fc 8e fd e6 88 8b fc 81 eb 80 fd 81 83 87 f7 fb fc 89 fd 82 ff}  //weight: 1, accuracy: High
        $x_1_6 = {66 c7 44 38 fd 65 78 c6 44 38 ff 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

