rule TrojanSpy_Win32_Iedown_A_2147599348_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Iedown.gen!A"
        threat_id = "2147599348"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Iedown"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "InternetReadFile" ascii //weight: 1
        $x_1_3 = "InternetGetCookieA" ascii //weight: 1
        $x_1_4 = "HttpSendRequestA" ascii //weight: 1
        $x_1_5 = "DllCanUnloadNow" ascii //weight: 1
        $x_1_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects" ascii //weight: 1
        $x_1_7 = "&POSTDATA=NOW&" ascii //weight: 1
        $x_1_8 = "http://203.223.159.229/~user1/errors/db3.php?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

