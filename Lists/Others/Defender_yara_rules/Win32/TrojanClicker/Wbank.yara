rule TrojanClicker_Win32_Wbank_A_2147596371_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Wbank.A"
        threat_id = "2147596371"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Wbank"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Fw-bank.co.kr" ascii //weight: 1
        $x_1_2 = "%s/ctrl/search.php?id=%s&wd=%s&tb=%s&code1=%sbb1" ascii //weight: 1
        $x_1_3 = "%s/ctrl/search.php?id=%s&wd=%s&tb=%s&code1=%sbb2" ascii //weight: 1
        $x_1_4 = "cashon.co.kr/search/search.php?where=total&query=" ascii //weight: 1
        $x_1_5 = "go.redbug.co.kr/go2.html?keyword=" ascii //weight: 1
        $x_1_6 = "go.netpia.com/search.asp?com=dreamwiz_plugin&keyword=" ascii //weight: 1
        $x_1_7 = "go.netpia.com/nlia.asp?com=dreamwiz_plugin&keyword=" ascii //weight: 1
        $x_1_8 = "search.netpia.com/search.asp?action=search&ver=5.0&com=netpia_nb&keyword=" ascii //weight: 1
        $x_1_9 = "go.netpia.com/nlia.asp?com=netpia_plugin&keyword=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

