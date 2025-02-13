rule Trojan_Win32_Opachki_D_154081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Opachki.D"
        threat_id = "154081"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Opachki"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 55 53 45 52 50 52 4f 46 49 4c 45 25 5c 63 7a 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {2f 78 75 69 2f 6d 61 6e 64 61 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_3 = {61 64 76 65 72 5f 69 64 00}  //weight: 1, accuracy: High
        $x_1_4 = "/js.php?u=%d&b=%d&a=%d\"></script>" ascii //weight: 1
        $x_1_5 = {6c 6f 72 65 72 5c 52 65 67 69 73 74 72 61 74 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_6 = {25 55 53 45 52 50 52 4f 46 49 4c 45 25 5c 70 69 7a 64 61 5f 63 7a 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_7 = {75 73 65 72 69 6e 69 74 00 00 00 00 6e 74 64 65 76 69 63 65 00}  //weight: 1, accuracy: High
        $x_1_8 = {26 66 5b 5d 3d 6c 6f 61 64 65 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Opachki_I_172450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Opachki.I"
        threat_id = "172450"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Opachki"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "&f[]=loader" ascii //weight: 1
        $x_1_2 = {83 c0 e0 75 12 80 ea 61 80 fa 19 77 0a 41 8a 14 0e 8a 01 84 d2 75 ?? 80 39 00 74 ?? ff 45 08 8b 45 08 8a 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

