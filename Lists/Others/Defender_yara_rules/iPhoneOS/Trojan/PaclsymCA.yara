rule Trojan_iPhoneOS_PaclsymCA_A_2147753001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:iPhoneOS/PaclsymCA.A!MTB"
        threat_id = "2147753001"
        type = "Trojan"
        platform = "iPhoneOS: "
        family = "PaclsymCA"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com.saurik.Cydia" ascii //weight: 2
        $x_1_2 = "/etc/apt/sources.list.d/cydia.list" ascii //weight: 1
        $x_1_3 = "SetCydiaVisibilityProcessor" ascii //weight: 1
        $x_1_4 = "PasswordCaptureManager" ascii //weight: 1
        $x_1_5 = "RemoteCmdData" ascii //weight: 1
        $x_1_6 = "SyncSnapshotRulesMSG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

