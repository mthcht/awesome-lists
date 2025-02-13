rule Trojan_Win32_Madbot_2147620037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Madbot"
        threat_id = "2147620037"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Madbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KewlButtons" ascii //weight: 1
        $x_1_2 = "Microsoft Visual Studio\\VB98\\VB" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_4 = "Host: captcha.chat.yahoo.com" wide //weight: 1
        $x_1_5 = "Referer: MadDogInc" wide //weight: 1
        $x_1_6 = "POST /captcha1 HTTP/1.1" wide //weight: 1
        $x_1_7 = "User-Agent: Mozilla/4.0" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

