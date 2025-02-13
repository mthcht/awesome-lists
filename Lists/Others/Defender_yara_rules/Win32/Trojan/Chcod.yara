rule Trojan_Win32_Chcod_A_2147629135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chcod.A"
        threat_id = "2147629135"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chcod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_2 = "GetWindowsDirectoryA" ascii //weight: 1
        $x_1_3 = "OpenProcessToken" ascii //weight: 1
        $x_1_4 = "RegisterServiceCtrlHandlerA" ascii //weight: 1
        $x_1_5 = "Accept-Language: zh-cn" ascii //weight: 1
        $x_1_6 = "application/x-shockwave-flash, application/vnd.ms-excel" ascii //weight: 1
        $x_1_7 = "C:\\T.ini" ascii //weight: 1
        $x_1_8 = "0.0.1.1" ascii //weight: 1
        $x_1_9 = {83 c9 ff 33 c0 c6}  //weight: 1, accuracy: High
        $x_1_10 = {3c 2f 74 0d 84 c0 74 09 8a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

