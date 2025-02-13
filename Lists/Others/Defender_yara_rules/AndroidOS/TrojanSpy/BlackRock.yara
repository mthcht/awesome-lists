rule TrojanSpy_AndroidOS_BlackRock_A_2147760562_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/BlackRock.A!MTB"
        threat_id = "2147760562"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "BlackRock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/StartKeyLogs.txt" ascii //weight: 1
        $x_1_2 = "/Screen_Lock.txt" ascii //weight: 1
        $x_1_3 = "26kozQaKwRuNJ24t" ascii //weight: 1
        $x_1_4 = "MzVBOEU4RUExNzdDNTA3NzN2d4aaiU2eCF7zGpaxGnZoCUs4ByC63zVz9mHieQqu" ascii //weight: 1
        $x_1_5 = "Spam_on_contacts" ascii //weight: 1
        $x_1_6 = "StartKeyLogs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

