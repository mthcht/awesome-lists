rule Trojan_AndroidOS_Gumen_A_2147902752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Gumen.A!MTB"
        threat_id = "2147902752"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Gumen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/testabc/mytest" ascii //weight: 1
        $x_1_2 = "&execution=e1s2&_eventId=submit&username=" ascii //weight: 1
        $x_1_3 = "www.SUPER789.NET" ascii //weight: 1
        $x_1_4 = "SaxBookParser" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

