rule Trojan_AndroidOS_Regon_A_2147832909_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Regon.A!MTB"
        threat_id = "2147832909"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Regon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "upServerAppsList" ascii //weight: 1
        $x_1_2 = "upServerContactList" ascii //weight: 1
        $x_1_3 = "upServerCallLogs" ascii //weight: 1
        $x_1_4 = "isshowcard" ascii //weight: 1
        $x_1_5 = "hookcalls" ascii //weight: 1
        $x_1_6 = "get_browhist" ascii //weight: 1
        $x_1_7 = "set_injects" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

