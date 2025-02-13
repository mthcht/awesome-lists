rule TrojanDownloader_AndroidOS_Gapac_B_2147833847_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:AndroidOS/Gapac.B!MTB"
        threat_id = "2147833847"
        type = "TrojanDownloader"
        platform = "AndroidOS: Android operating system"
        family = "Gapac"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dandelionmob.com/ssp" ascii //weight: 1
        $x_1_2 = "s.ojiegame.com" ascii //weight: 1
        $x_1_3 = "StearActivity" ascii //weight: 1
        $x_1_4 = "openapp.jdmobile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

