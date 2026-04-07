rule Trojan_Win32_Steam_AMTB_2147966474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Steam!AMTB"
        threat_id = "2147966474"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Steam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Steam Desktop Authenticator" ascii //weight: 1
        $x_1_2 = "5272598351:AAGATcXay8QKvKdhusHW4aj9tA1uZZSad9w" ascii //weight: 1
        $x_1_3 = "1809511065:AAGaCnO4xXdbm4ZyHw57L21bQkKjuWGZNRE" ascii //weight: 1
        $x_1_4 = "hugzho's big brain" ascii //weight: 1
        $x_1_5 = "https://api.telegram.org/bot" ascii //weight: 1
        $x_1_6 = "/sendDocument?chat_id=" ascii //weight: 1
        $x_1_7 = "&caption=NEW MAFiLE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

