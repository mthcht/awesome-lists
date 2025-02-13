rule Spammer_Win32_Spawl_A_2147621075_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Spawl.A"
        threat_id = "2147621075"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Spawl"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {73 74 72 69 6b 65 62 61 63 6b 00 00 25 63 00 00 25 64 00 00 25 6d 65 73 73 61 67 65 69 64 25 00 25 62 6f 75 6e 64 61 72 79 34 25}  //weight: 3, accuracy: High
        $x_1_2 = {25 62 6f 75 6e 64 61 72 79 25 00 00 6d 73 00 00 25 64 61 74 65 25 00 00 25 74 6f 5f 65 6d 61 69 6c 25 00 00 25 75 25 00 25 66 72 6f 6d 5f 6e 61 6d}  //weight: 1, accuracy: High
        $x_1_3 = {61 64 6d 69 6e 40 73 6d 74 70 2e [0-8] 2e 72 75 00 00 00 61 64 6d 69 6e 40 73 6d 74 70 2e [0-8] 2e 72 75 00}  //weight: 1, accuracy: Low
        $x_1_4 = {72 61 74 6f 72 00 47 45 54 20 68 74 74 70 3a 2f 2f 36 39 2e 35 30 2e 31 37 30 2e 31 30 30 2f 6d 61 69 6c 73 2f 69 6e}  //weight: 1, accuracy: High
        $x_1_5 = {2a 2e 64 62 78 00 00 00 75 73 65 72 70 72 6f 66 69 6c 65 00 25 75 73 65 72 70 72 6f 66 69 6c 65 25 00}  //weight: 1, accuracy: High
        $x_1_6 = {25 74 6f 5f 65 6d 61 69 6c 25 00 00 25 75 25 00 25 66 72 6f 6d 5f 6e 61 6d 65 25 00 25 73 75 62 6a 65 63 74 25 00 00 00 25 66 72 6f 6d 5f 65 6d 61 69 6c 25 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Spammer_Win32_Spawl_B_2147621076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Spawl.B"
        threat_id = "2147621076"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Spawl"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "90"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {25 66 72 6f 6d 5f 6e 61 6d 65 25 00 25 73 75 62 6a 65 63 74 25}  //weight: 10, accuracy: High
        $x_10_2 = "StartProcessAtWinLogon" ascii //weight: 10
        $x_10_3 = "Asynchronous" ascii //weight: 10
        $x_10_4 = "StopProcessAtWinLogoff" ascii //weight: 10
        $x_10_5 = {4e 6f 74 69 66 79 5c 00 57 69 6e 6c 6f 67 6f 6e 5c}  //weight: 10, accuracy: High
        $x_10_6 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)" ascii //weight: 10
        $x_10_7 = "Say BY-BY" ascii //weight: 10
        $x_10_8 = {62 65 73 74 5f 73 65 61 72 63 68 00 70 61 74 68 20 3d}  //weight: 10, accuracy: High
        $x_10_9 = "strikeback" ascii //weight: 10
        $x_1_10 = "http://gaagle2.com/" ascii //weight: 1
        $x_1_11 = "207.226.178.158" ascii //weight: 1
        $x_1_12 = "206.161.205.142" ascii //weight: 1
        $x_1_13 = "admin@smtp.rambler.ru" ascii //weight: 1
        $x_1_14 = "admin@smtp.yandex.ru" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((9 of ($x_10_*))) or
            (all of ($x*))
        )
}

