rule Trojan_AndroidOS_Spyagent_T_2147842750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Spyagent.T"
        threat_id = "2147842750"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Spyagent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getEnableReadFiles" ascii //weight: 1
        $x_1_2 = "getNewServerUrl3" ascii //weight: 1
        $x_1_3 = "isCOnionEnabled" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Spyagent_HA_2147852731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Spyagent.HA"
        threat_id = "2147852731"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Spyagent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TwTextChange" ascii //weight: 1
        $x_1_2 = "mFbOldText" ascii //weight: 1
        $x_1_3 = "mPubgGmailText" ascii //weight: 1
        $x_1_4 = "GmsOldText" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

