rule Trojan_Win32_Dreef_A_2147632298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dreef.A"
        threat_id = "2147632298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dreef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 6f 68 00 72 73 68 00 6e 65 77 3e 00}  //weight: 1, accuracy: High
        $x_1_2 = {50 61 73 73 57 6f 72 64 3a 0d 0a 00 20 69 73 20 63 6f 6e 6e 65 63 74 69 6e 67 00}  //weight: 1, accuracy: High
        $x_1_3 = {31 39 37 2c 35 34 2c 32 31 34 2c 37 30 2c 32 32 36 2c 38 36 2c 31 33 35 00}  //weight: 1, accuracy: High
        $x_1_4 = {31 39 37 2c 37 31 2c 38 36 2c 32 31 34 2c 37 2c 31 39 37 2c 31 31 39 2c 38 37 2c 32 32 2c 38 37 2c 35 34 2c 31 39 38 2c 37 31 2c 35 35 2c 32 32 36 2c 38 36 2c 31 33 35 00}  //weight: 1, accuracy: High
        $x_1_5 = {31 30 32 2c 33 39 2c 38 36 2c 38 36 2c 37 30 2c 37 30 2c 32 33 30 2c 35 35 2c 32 32 36 2c 31 30 32 2c 33 39 2c 38 36 2c 38 36 2c 37 30 2c 37 30 2c 32 33 30 2c 35 35 2c 32 32 36 2c 35 34 2c 32 34 36 2c 32 31 34 00}  //weight: 1, accuracy: High
        $x_1_6 = {4d 69 63 72 6f 73 6f 66 74 20 57 69 6e 64 6f 77 73 20 4e 54 35 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

