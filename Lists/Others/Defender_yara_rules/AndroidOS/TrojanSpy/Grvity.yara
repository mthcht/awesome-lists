rule TrojanSpy_AndroidOS_Grvity_A_2147766616_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Grvity.A!MTB"
        threat_id = "2147766616"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Grvity"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {74 74 70 3a 2f 2f 6e [0-3] 2e 6e 6f 72 74 6f 6e 75 70 64 61 74 65 73 2e 6f 6e 6c 69 6e 65}  //weight: 3, accuracy: Low
        $x_1_2 = "download.savitabhabi" ascii //weight: 1
        $x_1_3 = "GetActivePrivateDomain" ascii //weight: 1
        $x_1_4 = "/system/bin/ping -c 1" ascii //weight: 1
        $x_1_5 = "getCallsLogs" ascii //weight: 1
        $x_1_6 = "getSMSList" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

