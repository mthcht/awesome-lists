rule Backdoor_MacOS_iWorm_A_2147735811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/iWorm.A"
        threat_id = "2147735811"
        type = "Backdoor"
        platform = "MacOS: "
        family = "iWorm"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "/System/Library/StartupItems/divx/StartupParameters.plist" ascii //weight: 5
        $x_5_2 = "chmod 755 /System/Library/StartupItems/divx/divx" ascii //weight: 5
        $x_1_3 = "Description = \"divx\"" ascii //weight: 1
        $x_1_4 = "banadd" ascii //weight: 1
        $x_1_5 = "p2plock" ascii //weight: 1
        $x_1_6 = "p2pihistsize" ascii //weight: 1
        $x_1_7 = "p2ppeerport" ascii //weight: 1
        $x_1_8 = "sendlogs" ascii //weight: 1
        $x_1_9 = "uptime" ascii //weight: 1
        $x_5_10 = "qwfojzlk.freehostia.com" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

