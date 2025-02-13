rule Trojan_Win32_NSISDow_A_2147851339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISDow.A!MTB"
        threat_id = "2147851339"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISDow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "tgbnhyhtgbnhyttgbnhyttgbnhyptgbnhy:tgbnhy/tgbnhy/tgbnhywtgbnhywtgbnhywtgbnhy.tgbnhy" ascii //weight: 2
        $x_2_2 = "/useragent" ascii //weight: 2
        $x_2_3 = "/NOPROXY" ascii //weight: 2
        $x_2_4 = "SOFTWARE\\Botha" ascii //weight: 2
        $x_2_5 = "9khso82n" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

