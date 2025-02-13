rule Trojan_MacOS_Yort_A_2147744955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Yort.A!MTB"
        threat_id = "2147744955"
        type = "Trojan"
        platform = "MacOS: "
        family = "Yort"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "towingoperations.com/chat/chat.php" ascii //weight: 2
        $x_1_2 = "baseballcharlemagnelegardeur.com/wp-content/languages/common.php" ascii //weight: 1
        $x_1_3 = "tangowithcolette.com/pages/common.php" ascii //weight: 1
        $x_1_4 = "ReplyTroyInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

