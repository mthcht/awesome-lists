rule Trojan_Win32_Ziconarch_A_2147680202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ziconarch.A"
        threat_id = "2147680202"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ziconarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "logincoin.ru" ascii //weight: 1
        $x_1_2 = "secondcoin.ru" ascii //weight: 1
        $x_1_3 = "ZipCoin_original" ascii //weight: 1
        $x_1_4 = "/zipcoin.ru/archrf/?archref=" ascii //weight: 1
        $x_1_5 = "Sending SMS you agree with the user agreement." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

