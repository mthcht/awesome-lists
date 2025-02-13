rule Trojan_AndroidOS_Monocle_B_2147786695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Monocle.B"
        threat_id = "2147786695"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Monocle"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getUserDictList" ascii //weight: 1
        $x_1_2 = "getKeyLogging" ascii //weight: 1
        $x_1_3 = "GetInterfacesStates" ascii //weight: 1
        $x_1_4 = "ChangeCallRecordMode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Monocle_C_2147786696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Monocle.C"
        threat_id = "2147786696"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Monocle"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uploadFileToAgentCmd" ascii //weight: 1
        $x_1_2 = "Android/data/serv8202965" ascii //weight: 1
        $x_1_3 = "EVENT_APP_CHANGE_STATE" ascii //weight: 1
        $x_1_4 = "FakeWrongCmd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

