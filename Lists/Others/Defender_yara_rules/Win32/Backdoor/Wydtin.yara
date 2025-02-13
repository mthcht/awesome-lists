rule Backdoor_Win32_Wydtin_A_2147697811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Wydtin.A"
        threat_id = "2147697811"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Wydtin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "dywt.com.cn" ascii //weight: 1
        $x_1_2 = "=?gb2312?B?" ascii //weight: 1
        $x_1_3 = "d09f2340818511d396f6aaf844c7e325" ascii //weight: 1
        $x_1_4 = "F7FC1AE45C5C4758AF03EF19F18A395D" ascii //weight: 1
        $x_1_5 = {4c 4f 47 49 4e [0-32] 45 48 4c 4f 20 25 73}  //weight: 1, accuracy: Low
        $x_1_6 = "MAIL FROM:<%s>" ascii //weight: 1
        $x_1_7 = "RCPT TO:<%s>" ascii //weight: 1
        $x_1_8 = {61 74 74 61 63 68 6d 65 6e 74 [0-16] 66 69 6c 65 6e 61 6d 65 3d 25 73}  //weight: 1, accuracy: Low
        $x_1_9 = "\\Windows\\CurrentVersion\\Policies\\System\\DisableTaskMgr" ascii //weight: 1
        $x_1_10 = {65 78 65 66 69 6c 65 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 5c 00 51 51 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_11 = "smtp.qq.com" ascii //weight: 1
        $x_1_12 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 63 69 74 79 31 5c 00 2e 6a 70 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Wydtin_A_2147697811_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Wydtin.A"
        threat_id = "2147697811"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Wydtin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "dywt.com.cn" ascii //weight: 1
        $x_1_2 = "=?gb2312?B?" ascii //weight: 1
        $x_1_3 = {6b 72 6e 6c 6e 2e 66 6e 72 [0-5] 64 30 39 66 32 33 34 30 38 31 38 35 31 31 64 33 39 36 66 36 61 61 66 38 34 34 63 37 65 33 32 35}  //weight: 1, accuracy: Low
        $x_1_4 = {70 6f 70 33 [0-5] 36 36 33 39 31 33 34 45 38 32 33 34 34 36 33 37 41 37 31 41 42 31 44 36 42 37 30 43 32 30 35 31}  //weight: 1, accuracy: Low
        $x_1_5 = {69 6e 74 65 72 6e 65 74 [0-5] 37 30 37 63 61 33 37 33 32 32 34 37 34 66 36 63 61 38 34 31 66 30 65 32 32 34 66 34 62 36 32 30}  //weight: 1, accuracy: Low
        $x_1_6 = {4c 4f 47 49 4e [0-32] 45 48 4c 4f 20 25 73}  //weight: 1, accuracy: Low
        $x_1_7 = "MAIL FROM:<%s>" ascii //weight: 1
        $x_1_8 = "RCPT TO:<%s>" ascii //weight: 1
        $x_1_9 = {61 74 74 61 63 68 6d 65 6e 74 [0-16] 66 69 6c 65 6e 61 6d 65 3d 25 73}  //weight: 1, accuracy: Low
        $x_1_10 = "ConnectFTPServer" ascii //weight: 1
        $x_1_11 = "GetFtpFile" ascii //weight: 1
        $x_1_12 = "PutFtpFile" ascii //weight: 1
        $x_1_13 = "GetHttpFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (12 of ($x*))
}

