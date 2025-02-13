rule TrojanDropper_AndroidOS_BankerAgent_X_2147794529_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/BankerAgent.X"
        threat_id = "2147794529"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "BankerAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "dn_ssl" ascii //weight: 2
        $x_2_2 = "decrypt" ascii //weight: 2
        $x_1_3 = "scrt.apk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

