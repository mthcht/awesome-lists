rule Backdoor_Win32_Ziyazo_A_2147685083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ziyazo.A"
        threat_id = "2147685083"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ziyazo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ZiYangZhouhu" ascii //weight: 2
        $x_2_2 = {25 30 34 64 2d 25 30 32 64 2d 25 30 32 64 20 25 30 32 64 3a 25 30 32 64 09 25 31 34 64}  //weight: 2, accuracy: High
        $x_2_3 = {25 30 34 64 2d 25 30 32 64 2d 25 30 32 64 20 25 30 32 64 3a 25 30 32 64 09 3c 44 49 52 3e}  //weight: 2, accuracy: High
        $x_2_4 = "[cd %s] error with code: %d I will sleep %d Minutes, Goodbye, Workaholic!" ascii //weight: 2
        $x_2_5 = "[Serch+]?%04d-%02d-%02d %02d:%02d%15d %s%s" ascii //weight: 2
        $x_2_6 = "%s||%s||%s||%s||%s" ascii //weight: 2
        $x_1_7 = "[Remote] File Start UpLoad At:%d Bytes" ascii //weight: 1
        $x_1_8 = "[Remote] Put [%s] Failed With Code: %d" ascii //weight: 1
        $x_1_9 = "[Remote] File Start DownLoad At:%d Bytes" ascii //weight: 1
        $x_1_10 = "[Remote] Get [%s] Failed With Code: %d" ascii //weight: 1
        $x_1_11 = "*JiangMin*" wide //weight: 1
        $x_1_12 = "*Trend Micro*" wide //weight: 1
        $x_1_13 = "*Kaspersky*" wide //weight: 1
        $x_1_14 = "*Symantec*" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            (all of ($x*))
        )
}

