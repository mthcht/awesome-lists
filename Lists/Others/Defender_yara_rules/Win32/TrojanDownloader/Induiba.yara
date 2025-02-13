rule TrojanDownloader_Win32_Induiba_A_2147626581_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Induiba.A"
        threat_id = "2147626581"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Induiba"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://%s%smac=%s&ver=%s" ascii //weight: 1
        $x_1_2 = "/count.asp?" ascii //weight: 1
        $x_1_3 = "if exist \"%s\" goto" ascii //weight: 1
        $x_1_4 = "baidu.info/Files/default.jpg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

