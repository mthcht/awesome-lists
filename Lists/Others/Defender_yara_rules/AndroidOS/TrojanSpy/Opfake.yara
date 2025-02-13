rule TrojanSpy_AndroidOS_Opfake_G_2147775779_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Opfake.G!MTB"
        threat_id = "2147775779"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Opfake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lfkjsgmjl/ceinnykas/basgxjkff;" ascii //weight: 1
        $x_1_2 = "Lveykimsi/puaqck/lktcwa;" ascii //weight: 1
        $x_1_3 = "/etqsauya;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

