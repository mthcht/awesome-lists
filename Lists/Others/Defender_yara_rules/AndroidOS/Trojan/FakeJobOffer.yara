rule Trojan_AndroidOS_FakeJobOffer_A_2147823818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeJobOffer.A!MTB"
        threat_id = "2147823818"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeJobOffer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/biggboss6/Tatashow" ascii //weight: 1
        $x_1_2 = "ad.doubleclick.net/N6714/adj/SAAVNAndroidWeb" ascii //weight: 1
        $x_1_3 = "trackVdopia" ascii //weight: 1
        $x_1_4 = "trackZestAdz" ascii //weight: 1
        $x_1_5 = "fetchedHomeData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

