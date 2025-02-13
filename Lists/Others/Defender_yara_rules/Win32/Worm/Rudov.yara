rule Worm_Win32_Rudov_2147606831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Rudov"
        threat_id = "2147606831"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Rudov"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "63"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "FastMM Borland Edition " ascii //weight: 10
        $x_10_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 10
        $x_10_3 = "AntiDurov" ascii //weight: 10
        $x_10_4 = "Durov VKontakte Service" ascii //weight: 10
        $x_10_5 = "WSAAsyncSelect" ascii //weight: 10
        $x_10_6 = "http://vkontakte.ru" ascii //weight: 10
        $x_1_7 = "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7" ascii //weight: 1
        $x_1_8 = "/mail.php?act=write&to=" ascii //weight: 1
        $x_1_9 = "<input type=\"hidden\" id=\"to_reply\" name=\"to_reply\" value=\"" ascii //weight: 1
        $x_1_10 = "\\Microsoft\\Windows\\Cookies" ascii //weight: 1
        $x_1_11 = "-kill" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

