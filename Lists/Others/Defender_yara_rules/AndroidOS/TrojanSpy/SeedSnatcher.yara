rule TrojanSpy_AndroidOS_SeedSnatcher_AMTB_2147958806_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SeedSnatcher!AMTB"
        threat_id = "2147958806"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SeedSnatcher"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "a2decxd8syw7k.top" ascii //weight: 2
        $x_1_2 = "fake_dex.jar" ascii //weight: 1
        $x_1_3 = "saveSms" ascii //weight: 1
        $x_1_4 = "saveContacts" ascii //weight: 1
        $x_1_5 = "saveMnemonics" ascii //weight: 1
        $x_1_6 = "saveCallLog" ascii //weight: 1
        $x_1_7 = "Seed_Phrase_or_Private_Key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

