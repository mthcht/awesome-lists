rule Trojan_AndroidOS_Vidro_A_2147782824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Vidro.A!MTB"
        threat_id = "2147782824"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Vidro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vid4droid.com/ping/" ascii //weight: 1
        $x_1_2 = "feature_sms" ascii //weight: 1
        $x_1_3 = "sexgoesmobile.net" ascii //weight: 1
        $x_1_4 = "force_update" ascii //weight: 1
        $x_1_5 = "BilligManager" ascii //weight: 1
        $x_1_6 = "Lcom/vid4droid/SmsReceiver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

