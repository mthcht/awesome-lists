rule Trojan_AndroidOS_BadCall_A_2147782860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BadCall.A"
        threat_id = "2147782860"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BadCall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CMD_PROXY_MANACK" ascii //weight: 1
        $x_1_2 = "CMD_READ_WEBHIS" ascii //weight: 1
        $x_1_3 = "proxyManAck" ascii //weight: 1
        $x_1_4 = "m_strKeepLinkRsp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

