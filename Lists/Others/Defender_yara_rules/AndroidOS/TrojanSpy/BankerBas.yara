rule TrojanSpy_AndroidOS_BankerBas_A_2147760210_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/BankerBas.A!MTB"
        threat_id = "2147760210"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "BankerBas"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "anywheresoftware.b4a" ascii //weight: 1
        $x_1_2 = "uros_5.sms_and_contacts" ascii //weight: 1
        $x_1_3 = "are you drinking" ascii //weight: 1
        $x_1_4 = "Did you forget to call Activity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

