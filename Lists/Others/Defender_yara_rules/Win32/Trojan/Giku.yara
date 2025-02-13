rule Trojan_Win32_Giku_A_2147631842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Giku.A"
        threat_id = "2147631842"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Giku"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 6f 66 74 77 61 72 65 5c 25 63 62 50 25 63 75 67 25 63 6e 5c 42 25 63 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 25 63 62 50 25 63 75 25 63 69 6e 5c 00 00 00 67 25 63 69 25 63 68 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_1_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 41 70 70 20 50 61 74 68 73 5c 49 45 25 63 50 4c 4f 25 63 45 2e 45 58 45 00}  //weight: 1, accuracy: High
        $x_1_4 = {5f 4a 61 76 61 5f 62 72 5f 48 6a 78 5f 63 69 74 64 40 31 32 00 5f 4a 61 76 61 5f 62 72 5f 48 6a 78 5f 67 63 67 66 33 40 38}  //weight: 1, accuracy: High
        $x_1_5 = {4a 61 76 61 5f 62 72 5f 48 6a 78 5f 63 69 74 64 00 4a 61 76 61 5f 62 72 5f 48 6a 78 5f 67 63 67 66 33}  //weight: 1, accuracy: High
        $x_1_6 = "\\G%c%clu%cin\\%cb\\%cbp%ci%c3.g%cp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

