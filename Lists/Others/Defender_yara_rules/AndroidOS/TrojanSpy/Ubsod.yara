rule TrojanSpy_AndroidOS_Ubsod_A_2147744868_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Ubsod.A!MTB"
        threat_id = "2147744868"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Ubsod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mob0esd.ru" ascii //weight: 1
        $x_1_2 = "aps90tel.ru" ascii //weight: 1
        $x_1_3 = "mob1lihelp.ru" ascii //weight: 1
        $x_1_4 = "delay.fullscreen" ascii //weight: 1
        $x_1_5 = "screen locked" ascii //weight: 1
        $x_1_6 = "adminDisabled" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

