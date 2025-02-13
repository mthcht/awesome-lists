rule TrojanSpy_AndroidOS_DDLight_A_2147646275_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/DDLight.A"
        threat_id = "2147646275"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "DDLight"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "InstalledProductInfo" ascii //weight: 1
        $x_1_2 = "/lightdd/CoreService" ascii //weight: 1
        $x_1_3 = "prefer.dat" ascii //weight: 1
        $x_1_4 = "MobileInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_DDLight_B_2147646276_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/DDLight.B"
        threat_id = "2147646276"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "DDLight"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AppManager.java" ascii //weight: 1
        $x_1_2 = "nextIntervel" ascii //weight: 1
        $x_1_3 = "intervel" ascii //weight: 1
        $x_1_4 = "saveNextFeedbackTime" ascii //weight: 1
        $x_1_5 = "SubCoopID" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

