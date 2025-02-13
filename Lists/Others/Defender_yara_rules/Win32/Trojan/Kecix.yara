rule Trojan_Win32_Kecix_A_2147685516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kecix.A"
        threat_id = "2147685516"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kecix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\USER\\Desktop\\eklenti" wide //weight: 1
        $x_1_2 = "\\ahmet.exe\\" wide //weight: 1
        $x_1_3 = {65 78 65 63 69 6b 00}  //weight: 1, accuracy: High
        $x_1_4 = {4d 6f 64 75 6c 65 31 00 63 6c 73 4d 44 35}  //weight: 1, accuracy: High
        $x_1_5 = {2f 00 75 00 70 00 64 00 61 00 74 00 65 00 [0-2] 2e 00 74 00 78 00 74 00 23 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_6 = "/manifest.json#http://" wide //weight: 1
        $x_1_7 = ".js#http://" wide //weight: 1
        $x_1_8 = ".png#http://" wide //weight: 1
        $x_1_9 = {2f 00 65 00 78 00 74 00 65 00 6e 00 73 00 69 00 6f 00 6e 00 [0-2] 2e 00 73 00 71 00 6c 00 69 00 74 00 65 00 23 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

