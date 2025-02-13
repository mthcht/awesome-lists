rule Adware_AndroidOS_Viser_A_353153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Viser.A!MTB"
        threat_id = "353153"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Viser"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = ".vserv.mobi/delivery/ti.php" ascii //weight: 10
        $x_10_2 = ".vserv.mobi/test/ti.php" ascii //weight: 10
        $x_1_3 = "/VservAd" ascii //weight: 1
        $x_1_4 = "mustSeeAdMsg" ascii //weight: 1
        $x_1_5 = "callKillProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

