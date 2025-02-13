rule PWS_Win32_QQShou_2147566902_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQShou"
        threat_id = "2147566902"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQShou"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "X-Mailer: QqGhost [ch]" ascii //weight: 2
        $x_2_2 = "X-Mailer: LCMailer [ch]" ascii //weight: 2
        $x_2_3 = {22 00 00 00 72 66 77 6d 61 69 6e 00}  //weight: 2, accuracy: High
        $x_1_4 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" ascii //weight: 1
        $x_1_5 = "www.chuanhua.net" ascii //weight: 1
        $x_1_6 = "chuanhua.nease.net" ascii //weight: 1
        $x_1_7 = "RCPT TO:<%s>" ascii //weight: 1
        $x_1_8 = "MAIL FROM:<%s>" ascii //weight: 1
        $x_1_9 = {00 74 65 6d 70 7e 33 00}  //weight: 1, accuracy: High
        $x_1_10 = "GetPixel" ascii //weight: 1
        $n_15_11 = "Capture.dll" ascii //weight: -15
        $n_15_12 = "MediaTransmit.dll" ascii //weight: -15
        $n_15_13 = {4e 65 74 44 69 73 6b 44 4c 4c 2e 64 6c 6c 00 42 61 73 65 36 34 44 65 63 6f 64 65 00}  //weight: -15, accuracy: High
        $n_15_14 = "PolicyManage.dll" ascii //weight: -15
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

