rule Trojan_MacOS_LooseMaque_A_2147745483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/LooseMaque.A!MTB"
        threat_id = "2147745483"
        type = "Trojan"
        platform = "MacOS: "
        family = "LooseMaque"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "stfj.net/loselose/highscore.php" ascii //weight: 1
        $x_1_2 = "/apps/zach/virus/" ascii //weight: 1
        $x_1_3 = "killing in lose/lose deletes your files" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

