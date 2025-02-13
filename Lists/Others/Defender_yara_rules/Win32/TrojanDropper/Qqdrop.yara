rule TrojanDropper_Win32_Qqdrop_B_2147650929_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Qqdrop.B"
        threat_id = "2147650929"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Qqdrop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\Documents and Settings\\All Users\\Application Data\\Tencent\\QQDownload\\QQ.exe" ascii //weight: 1
        $x_1_2 = "QQ.HLP" ascii //weight: 1
        $x_1_3 = "QQDownloadRecordPath" ascii //weight: 1
        $x_1_4 = "QQ.INI" ascii //weight: 1
        $x_1_5 = "%s\\%s.lnk" ascii //weight: 1
        $x_1_6 = {c6 44 24 0c ?? c6 44 24 0d ?? c6 44 24 0e ?? c6 44 24 0f ?? c6 44 24 10 ?? c6 44 24 11 ?? c6 44 24 12 ?? c6 44 24 13 ?? c6 44 24 14 ?? c6 44 24 15 ?? c6 44 24 16 ?? c6 44 24 17 ?? c6 44 24 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

