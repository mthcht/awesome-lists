rule Backdoor_Win32_Masteseq_AC_2147599764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Masteseq.AC"
        threat_id = "2147599764"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Masteseq"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_2 = "%s\\Internet Explorer\\iexplorer.exe" ascii //weight: 1
        $x_1_3 = "%s\\Internet Explorer\\iexplore.exe" ascii //weight: 1
        $x_1_4 = "POST /cgi-bin/cgi_proxy?cl=1 HTTP/1.1" ascii //weight: 1
        $x_1_5 = "User-Agent: Mozilla/4.0 (compatible; MSIE 5.0; Windows 95)" ascii //weight: 1
        $x_1_6 = "Host: %s" ascii //weight: 1
        $x_1_7 = "msgqueue_msg1_data_%08X" ascii //weight: 1
        $x_1_8 = "m_server_work_time" ascii //weight: 1
        $x_1_9 = "\\temp_%d.bat" ascii //weight: 1
        $x_1_10 = "SOFTWARE\\Numega" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

