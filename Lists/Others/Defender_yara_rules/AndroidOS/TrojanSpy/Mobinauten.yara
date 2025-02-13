rule TrojanSpy_AndroidOS_Mobinauten_A_2147782155_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Mobinauten.A!MTB"
        threat_id = "2147782155"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Mobinauten"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "de.mobinauten.smsspy" ascii //weight: 1
        $x_1_2 = "SMSSPY" ascii //weight: 1
        $x_1_3 = "Location Request received...I'm working" ascii //weight: 1
        $x_1_4 = "Found id of name systemnumber in contacts" ascii //weight: 1
        $x_1_5 = "SMS Database optimized" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Mobinauten_B_2147809013_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Mobinauten.B!MTB"
        threat_id = "2147809013"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Mobinauten"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "findAndSendLocation" ascii //weight: 1
        $x_1_2 = "SMSSPY" ascii //weight: 1
        $x_1_3 = "SMS_RECEIVED" ascii //weight: 1
        $x_1_4 = "onStartCommand" ascii //weight: 1
        $x_1_5 = "com/de/mobinauten/smsspy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

