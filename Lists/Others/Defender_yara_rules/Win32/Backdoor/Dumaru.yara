rule Backdoor_Win32_Dumaru_A_2147583261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Dumaru.gen!A"
        threat_id = "2147583261"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Dumaru"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HttpSendRequestA" ascii //weight: 1
        $x_1_2 = "InternetReadFile" ascii //weight: 1
        $x_1_3 = "\\dvp.log" ascii //weight: 1
        $x_1_4 = "\\SYSTEM32\\DRIVERS\\ETC\\hosts" ascii //weight: 1
        $x_1_5 = "Volk, ein REICH, ein Fuhrer !!!" ascii //weight: 1
        $x_1_6 = {64 76 70 64 2e 44 4c 4c 00 4d 48 6f 6f 6b 00 4d 55 6e 48 6f 6f 6b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

