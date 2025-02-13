rule TrojanSpy_AndroidOS_Boxer_A_2147782958_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Boxer.A!MTB"
        threat_id = "2147782958"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Boxer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "testAddContact" ascii //weight: 1
        $x_1_2 = "secret.jabox.ru" ascii //weight: 1
        $x_1_3 = "Joke-BOX" ascii //weight: 1
        $x_1_4 = "flirt." ascii //weight: 1
        $x_1_5 = "ss_jad.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

