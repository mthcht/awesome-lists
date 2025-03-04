rule PWS_Win32_QQPass_GP_2147695004_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQPass.GP"
        threat_id = "2147695004"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQPass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&Level=30&ToKen=%B5%C7%C2%BC%B1%A3%BB%A4%5BNO%5D%B6%FE%BC%B6%C3" ascii //weight: 1
        $x_1_2 = "i3.tietuku.com/801db876cdcaa96c.png" ascii //weight: 1
        $x_1_3 = "asp?Action=AddUser&Server=" ascii //weight: 1
        $x_1_4 = "qq.com/other/cilent/index2.shtml" ascii //weight: 1
        $x_1_5 = "getimage?aid=11000101&r=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

