rule Adware_AndroidOS_Pushads_U_418276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Pushads.U"
        threat_id = "418276"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Pushads"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getmJmMoney" ascii //weight: 1
        $x_1_2 = "getImgs_url2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

