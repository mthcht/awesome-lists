rule Worm_MacOS_Inqtana_A_2147747846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MacOS/Inqtana.A!MTB"
        threat_id = "2147747846"
        type = "Worm"
        platform = "MacOS: "
        family = "Inqtana"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "InqTanaHandler/InqTanaHandler.m" ascii //weight: 1
        $x_1_2 = "/tmp/stachliu" ascii //weight: 1
        $x_1_3 = "If you are seeing this then you are pwned" ascii //weight: 1
        $x_1_4 = "./authopen-CF_CHARSET.pl " ascii //weight: 1
        $x_1_5 = "./FailureToLaunch-ppc.pl" ascii //weight: 1
        $x_1_6 = "./excploit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

