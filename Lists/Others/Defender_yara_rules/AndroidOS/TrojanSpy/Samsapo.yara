rule TrojanSpy_AndroidOS_Samsapo_AS_2147782634_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Samsapo.AS!MTB"
        threat_id = "2147782634"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Samsapo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "oopsspoo.ru/index.php" ascii //weight: 1
        $x_1_2 = "has_phone_number" ascii //weight: 1
        $x_1_3 = "silenceRinger" ascii //weight: 1
        $x_1_4 = "BlockNums" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

