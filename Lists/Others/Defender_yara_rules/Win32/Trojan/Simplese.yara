rule Trojan_Win32_Simplese_2147494471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Simplese"
        threat_id = "2147494471"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Simplese"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "Server IS vulnerable!!!" ascii //weight: 5
        $x_5_2 = "Server is not vulnerable" ascii //weight: 5
        $x_5_3 = {53 65 72 76 65 72 20 64 6f 65 73 6e 27 74 20 73 65 65 6d 20 [0-8] 76 75 6c 6e 65 72 61 62 6c 65}  //weight: 5, accuracy: Low
        $x_5_4 = "Server crashed!" ascii //weight: 5
        $x_5_5 = "Fake Players DoS" ascii //weight: 5
        $x_5_6 = "aluigi@altervista.org" ascii //weight: 5
        $x_5_7 = "start fake players attack:" ascii //weight: 5
        $x_1_8 = {53 75 63 63 65 73 73 66 75 6c 20 57 53 41 53 54 41 52 54 55 50 20 6e 6f 74 20 79 65 74 20 70 65 72 66 6f 72 6d 65 64 00}  //weight: 1, accuracy: High
        $x_1_9 = {43 61 6e 27 74 20 73 65 6e 64 20 61 66 74 65 72 20 73 6f 63 6b 65 74 20 73 68 75 74 64 6f 77 6e 00}  //weight: 1, accuracy: High
        $x_1_10 = {55 73 61 67 65 3a 20 25 73 20 3c 68 6f 73 74 3e 0a 00}  //weight: 1, accuracy: High
        $x_1_11 = {55 73 61 67 65 3a 20 25 73 20 3c 73 65 72 76 65 72 3e 20 5b 70 6f 72 74 28 25 64 29 5d 0a 00}  //weight: 1, accuracy: High
        $x_2_12 = "Error: you must specify the server IP or hostname." ascii //weight: 2
        $x_2_13 = "fake operating system" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

