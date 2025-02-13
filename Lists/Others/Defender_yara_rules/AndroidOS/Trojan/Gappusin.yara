rule Trojan_AndroidOS_Gappusin_A_2147787560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Gappusin.A!MTB"
        threat_id = "2147787560"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Gappusin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "app.wapx.cn" ascii //weight: 2
        $x_1_2 = "smsMoney" ascii //weight: 1
        $x_1_3 = "STATE_FIGHTSMS" ascii //weight: 1
        $x_1_4 = "isAllAttack" ascii //weight: 1
        $x_1_5 = "action/account/spend" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

