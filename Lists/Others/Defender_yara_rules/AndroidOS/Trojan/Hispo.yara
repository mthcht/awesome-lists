rule Trojan_AndroidOS_Hispo_A_2147909892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Hispo.A"
        threat_id = "2147909892"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Hispo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://info.ku6.cn/clientRequest.htm" ascii //weight: 1
        $x_1_2 = "?method=hotKeyword&ct=android" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

