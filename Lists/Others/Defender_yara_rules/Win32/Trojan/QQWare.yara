rule Trojan_Win32_QQWare_EC_2147920732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QQWare.EC!MTB"
        threat_id = "2147920732"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QQWare"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ybtj.189.cn=380CB7A550031E0D740F28DC3FE88B80" ascii //weight: 1
        $x_1_2 = "DeleteUrlCacheEntryA" ascii //weight: 1
        $x_1_3 = "InternetGetCookieA" ascii //weight: 1
        $x_1_4 = "@iframe.ip138.com/ic.asp" ascii //weight: 1
        $x_1_5 = "ip.qq.com" ascii //weight: 1
        $x_1_6 = "pv.sohu.com/cityjson" ascii //weight: 1
        $x_1_7 = "counter.sina.com.cn/ip" ascii //weight: 1
        $x_1_8 = "ip.taobao.com/service/getIpInfo2.php?ip=myip" ascii //weight: 1
        $x_1_9 = "www.123cha.com/ip/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

