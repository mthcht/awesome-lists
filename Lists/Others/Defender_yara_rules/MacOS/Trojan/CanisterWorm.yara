rule Trojan_MacOS_CanisterWorm_SA_2147980928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/CanisterWorm.SA"
        threat_id = "2147980928"
        type = "Trojan"
        platform = "MacOS: "
        family = "CanisterWorm"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "eY0vgh1hLprRFj4SdZLY/YD7PKxcsWKGPIonew2HO/tYzgIoegVxPz_s3dk8HO/7kSFE6cmt57VA7yndsu6" ascii //weight: 1
        $x_1_2 = "32iD54fZH_hdaIbLLNjq/_yHmhjAWScxIsnTSe6Pf/pX1epMqeryzpajvIIoor/94vP8lRpc9HCDf37Tys6" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

