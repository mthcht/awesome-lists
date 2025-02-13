rule TrojanDownloader_MSIL_Artemis_RDB_2147896470_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Artemis.RDB!MTB"
        threat_id = "2147896470"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Artemis"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "0063116b-8e43-4eb5-951c-85b02083fe62" ascii //weight: 1
        $x_1_2 = "Gamewer Bypasser" ascii //weight: 1
        $x_1_3 = "//pastebin.com/raw/kutdYW3L" wide //weight: 1
        $x_1_4 = "//pastebin.com/raw/2dcF8Nn5" wide //weight: 1
        $x_1_5 = "Mozilla/5.0 (Macintosh; Intel Mac OS X x.y; rv:42.0) Gecko/20100101 Firefox/42.0" wide //weight: 1
        $x_1_6 = "Mercurial Grabber" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

