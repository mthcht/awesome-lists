rule BrowserModifier_Win32_Fotomoto_17662_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Fotomoto"
        threat_id = "17662"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Fotomoto"
        severity = "6"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "b2search" wide //weight: 1
        $x_1_2 = "fotomoto.DLL" ascii //weight: 1
        $x_1_3 = "ad_keywords_post_next_time" wide //weight: 1
        $x_1_4 = "ad_keywords_post" wide //weight: 1
        $x_1_5 = "ad_keywords_posted" wide //weight: 1
        $x_1_6 = "ad_keywords_interested" wide //weight: 1
        $x_1_7 = "counter_shopping_popup" wide //weight: 1
        $x_1_8 = "shopping_pop_interval" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Fotomoto_17662_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Fotomoto"
        threat_id = "17662"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Fotomoto"
        severity = "6"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "b2search" wide //weight: 3
        $x_3_2 = "http://cpvfeed.mediatraffic.com/feed.php?ac=%s&kw=%s&url=%s&ip=%s&rfo=xml" wide //weight: 3
        $x_3_3 = "%TEMP%\\aupd.exe" ascii //weight: 3
        $x_3_4 = "fotomoto.DLL" ascii //weight: 3
        $x_1_5 = "ezula_deniedsites" wide //weight: 1
        $x_1_6 = "ezula_dictionary" wide //weight: 1
        $x_1_7 = "ezula_enabled" wide //weight: 1
        $x_1_8 = "ezula_maxdup" wide //weight: 1
        $x_1_9 = "ezula_maxhilight" wide //weight: 1
        $x_1_10 = "internal_affiliate_id" wide //weight: 1
        $x_1_11 = "last_ezula_update_ID" wide //weight: 1
        $x_1_12 = "last_ezulasync" wide //weight: 1
        $x_1_13 = "mt_mediatraffic_enabled" wide //weight: 1
        $x_1_14 = "mt_popup_counter_notify" wide //weight: 1
        $x_1_15 = "next_fixed_ctx_popup_time" wide //weight: 1
        $x_1_16 = "next_mt_popup_time" wide //weight: 1
        $x_1_17 = "random_context_blacklist" wide //weight: 1
        $x_1_18 = "related_popups_enabled" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 13 of ($x_1_*))) or
            ((2 of ($x_3_*) and 10 of ($x_1_*))) or
            ((3 of ($x_3_*) and 7 of ($x_1_*))) or
            ((4 of ($x_3_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Fotomoto_B_132791_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Fotomoto.B"
        threat_id = "132791"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Fotomoto"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/smb/fixed_pop.php" wide //weight: 1
        $x_1_2 = "/smb/relatedget.php" wide //weight: 1
        $x_1_3 = "#show_message" wide //weight: 1
        $x_1_4 = "#related_update" wide //weight: 1
        $x_1_5 = "#pushlist_update" wide //weight: 1
        $x_1_6 = "#update_notify" wide //weight: 1
        $x_1_7 = "#fixed_update" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

