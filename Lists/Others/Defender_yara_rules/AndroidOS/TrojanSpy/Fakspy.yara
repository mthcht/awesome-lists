rule TrojanSpy_AndroidOS_Fakspy_A_2147767640_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Fakspy.A!MTB"
        threat_id = "2147767640"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Fakspy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "chatinfo.apk" ascii //weight: 1
        $x_1_2 = {49 74 73 20 61 20 53 79 73 74 65 6d 20 41 70 70 6c 69 63 61 74 69 6f 6e 20 0a 20 43 61 6e 27 74 20 75 6e 69 6e 73 74 61 6c 6c}  //weight: 1, accuracy: High
        $x_1_3 = "Can't Turn OFF Accessibility" ascii //weight: 1
        $x_1_4 = "/astroidService;" ascii //weight: 1
        $x_1_5 = "Ljii/optr/service/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_AndroidOS_Fakspy_B_2147767645_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Fakspy.B!MTB"
        threat_id = "2147767645"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Fakspy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Ljii/optr/service/utils/operf;" ascii //weight: 2
        $x_1_2 = "getInstalledApplications" ascii //weight: 1
        $x_1_3 = "getOriginatingAddress" ascii //weight: 1
        $x_1_4 = "Y29udGVudDovL3Ntcw==" ascii //weight: 1
        $x_1_5 = "L0FuZHJvaWQvLnN5c3RlbS8=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

