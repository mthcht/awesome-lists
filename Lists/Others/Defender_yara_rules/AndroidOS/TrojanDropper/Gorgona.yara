rule TrojanDropper_AndroidOS_Gorgona_A_2147834873_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Gorgona.A!MTB"
        threat_id = "2147834873"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Gorgona"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "WorkerRestarterService" ascii //weight: 1
        $x_1_2 = "InstallerRestarterService" ascii //weight: 1
        $x_1_3 = "InjectionHtmlActivity" ascii //weight: 1
        $x_1_4 = {3a 00 1b 00 6e 20 ?? ?? 04 00 0a 02 d8 03 00 ff df 02 02 7a 8e 22 50 02 01 00 3a 03 0e 00 d8 00 03 ff 6e 20 ?? ?? 34 00 0a 02 df 02 02 62 8e 22 50 02 01 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

