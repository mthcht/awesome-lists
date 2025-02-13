rule Trojan_MacOS_PPMiner_A_2147745513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/PPMiner.A!MTB"
        threat_id = "2147745513"
        type = "Trojan"
        platform = "MacOS: "
        family = "PPMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "safetycrew/pplauncher/pplauncher.go" ascii //weight: 1
        $x_1_2 = "main.minerCmd" ascii //weight: 1
        $x_1_3 = "main.cleanupMinerDirectory" ascii //weight: 1
        $x_1_4 = "main.dataMshelper" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

