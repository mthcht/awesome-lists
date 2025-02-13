rule TrojanSpy_AndroidOS_BadBazaar_A_2147898351_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/BadBazaar.A!MTB"
        threat_id = "2147898351"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "BadBazaar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PhoneFormats.dat" ascii //weight: 1
        $x_1_2 = "tps://flygram.org:4432/api/" ascii //weight: 1
        $x_1_3 = "AllowReadCallAndLog" ascii //weight: 1
        $x_1_4 = "org.telegram.FlyGram" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

