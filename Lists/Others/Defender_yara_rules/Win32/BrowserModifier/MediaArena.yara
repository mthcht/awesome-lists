rule BrowserModifier_Win32_MediaArena_362962_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/MediaArena"
        threat_id = "362962"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "MediaArena"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_ThankyouPageUrl" ascii //weight: 1
        $x_1_2 = "get_UninstallSearchUrl" ascii //weight: 1
        $x_1_3 = "get_StatsUrl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_MediaArena_362962_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/MediaArena"
        threat_id = "362962"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "MediaArena"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OfferScreen" ascii //weight: 1
        $x_1_2 = "IDS_DEFAULT_SEARCH_PROVIDER_DATA" ascii //weight: 1
        $x_1_3 = "IDS_SEARCH_BOX_OPTION" ascii //weight: 1
        $x_1_4 = "offerWindow" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

