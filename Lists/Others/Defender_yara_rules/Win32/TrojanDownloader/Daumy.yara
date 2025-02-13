rule TrojanDownloader_Win32_Daumy_A_2147645591_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Daumy.A"
        threat_id = "2147645591"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Daumy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "siteHost\"  \"clickurl" ascii //weight: 1
        $x_1_2 = "daum.net" ascii //weight: 1
        $x_1_3 = "rc25.overture.com" ascii //weight: 1
        $x_1_4 = "search.naver.com" ascii //weight: 1
        $x_1_5 = "404.dummywebsitedatabase.com" ascii //weight: 1
        $x_1_6 = "referurl=%s&pageurl=%s&p=0&dominfo" ascii //weight: 1
        $x_1_7 = "%s,%s,MINI,Y,sponsor,sponsor,N,%d,-1,X,%d,1" ascii //weight: 1
        $x_5_8 = {8b 44 24 68 8b 4c 24 64 8b 54 24 60 6a 05 50 51 52 68 ?? ?? ?? ?? 6a 00 ff 15}  //weight: 5, accuracy: Low
        $x_5_9 = {8b 50 08 51 8b 48 04 52 8b 10 51 52 8d 44 24 14 68 ?? ?? ?? ?? 50}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

