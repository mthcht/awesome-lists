rule TrojanDownloader_AndroidOS_Bsihai_A_2147829864_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:AndroidOS/Bsihai.A!MTB"
        threat_id = "2147829864"
        type = "TrojanDownloader"
        platform = "AndroidOS: Android operating system"
        family = "Bsihai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/doviz/turkiye/app" ascii //weight: 1
        $x_1_2 = "servis_calisiyor_mu" ascii //weight: 1
        $x_1_3 = "getLangingFile" ascii //weight: 1
        $x_1_4 = "piyasaozet" ascii //weight: 1
        $x_1_5 = "TAG_KRIPTO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

