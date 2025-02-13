rule PWS_Win32_Rumrux_A_2147595004_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Rumrux.gen!A"
        threat_id = "2147595004"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Rumrux"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {47 45 54 20 25 73 20 48 54 54 50 2f 31 2e 31 0d 0a 48 6f 73 74 3a 20 25 73 0d 0a 41 63 63 65 70 74 3a 20 2a 2f 2a 0d 0a 55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 35 2e 30 30 3b 20 25 73 29 0d 0a}  //weight: 1, accuracy: High
        $x_1_2 = {46 61 69 6c 65 64 20 74 6f 20 63 6f 6e 6e 65 63 74 2e 0a 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 64 6c 6c 63 61 63 68 65 5c 76 65 72 63 6c 73 69 64 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Desktop" ascii //weight: 1
        $x_1_5 = "Accept-Language: zh-cn" ascii //weight: 1
        $x_1_6 = {72 78 6d 72 75 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

