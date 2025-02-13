rule Trojan_Win32_FakeIE_ASG_2147893920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeIE.ASG!MTB"
        threat_id = "2147893920"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeIE"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "7bc69fc397b3d49d19f03b2d087dfcca51d144359a4699f9" wide //weight: 3
        $x_1_2 = "{8A0A0705-75BD-4B3B-8D1D-AF4FEF13C72B}" wide //weight: 1
        $x_1_3 = "{45C43BA8-14A8-4FD2-989B-1A099132B191}" wide //weight: 1
        $x_1_4 = "sogou.com/sogou?pid=sogou-netb-cbf8710b43df3f2c-4444" wide //weight: 1
        $x_1_5 = "bux8.com" wide //weight: 1
        $x_1_6 = "58wangwei.com" wide //weight: 1
        $x_1_7 = "588b.com" wide //weight: 1
        $x_1_8 = "****nonodihfghrect****" wide //weight: 1
        $x_1_9 = "kisafe.dll" wide //weight: 1
        $x_1_10 = "sentinelmfc.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FakeIE_GNH_2147893924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeIE.GNH!MTB"
        threat_id = "2147893924"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeIE"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hc\\hcard" ascii //weight: 1
        $x_1_2 = "kisafe.dll" ascii //weight: 1
        $x_1_3 = "sentinelmfc.dll" ascii //weight: 1
        $x_1_4 = "lk.brand.sogou.com" ascii //weight: 1
        $x_1_5 = "sogou.com/bill_cpc" ascii //weight: 1
        $x_1_6 = "nonodirhhect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FakeIE_ASW_2147923674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeIE.ASW!MTB"
        threat_id = "2147923674"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeIE"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RTv1iKtmhBfKumssK.dll" ascii //weight: 1
        $x_1_2 = "3E53_1F19.dll" ascii //weight: 1
        $x_1_3 = "www.1290.me" ascii //weight: 1
        $x_1_4 = "www.qvod456.com" ascii //weight: 1
        $x_1_5 = "pro.52icafe.com/quickpage/bookmark.js" wide //weight: 1
        $x_1_6 = "EyooSechelper2.dll" wide //weight: 1
        $x_1_7 = {68 67 02 00 00 68 b6 03 00 00 68 00 01 00 00 68 00 00 cf 10 53 53 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

