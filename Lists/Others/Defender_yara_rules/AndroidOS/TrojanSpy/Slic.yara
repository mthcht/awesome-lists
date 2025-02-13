rule TrojanSpy_AndroidOS_Slic_A_2147838683_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Slic.A!MTB"
        threat_id = "2147838683"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Slic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "load_sms.php" ascii //weight: 1
        $x_1_2 = "cards_json.php" ascii //weight: 1
        $x_1_3 = "/dev/cpuctl/tasks" ascii //weight: 1
        $x_1_4 = "wipeData" ascii //weight: 1
        $x_1_5 = "seiCujyg/vB/iuhlysui" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

