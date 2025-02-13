rule Trojan_AndroidOS_Fakelogo_A_2147838905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakelogo.A!MTB"
        threat_id = "2147838905"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakelogo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "byonet_maemax" ascii //weight: 1
        $x_1_2 = "mosisofts" ascii //weight: 1
        $x_1_3 = "sendSms" ascii //weight: 1
        $x_1_4 = "com/decryptstringmanager" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

