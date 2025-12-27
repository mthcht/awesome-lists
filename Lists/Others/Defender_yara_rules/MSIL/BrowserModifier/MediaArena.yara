rule BrowserModifier_MSIL_MediaArena_363871_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:MSIL/MediaArena"
        threat_id = "363871"
        type = "BrowserModifier"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MediaArena"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OfferScreen" ascii //weight: 1
        $x_1_2 = "offerWindow" ascii //weight: 1
        $x_1_3 = "I_DS_T_Y_P_OPENED" ascii //weight: 1
        $x_2_4 = "I_DS_FF_SET_TINGS_SEERRCH_ENG" ascii //weight: 2
        $x_1_5 = "BrowserLoadedWithUrl" ascii //weight: 1
        $x_2_6 = "MyPdfManager.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_MSIL_MediaArena_363871_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:MSIL/MediaArena"
        threat_id = "363871"
        type = "BrowserModifier"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MediaArena"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "PDFalcon" ascii //weight: 2
        $x_1_2 = "OfferScreen" ascii //weight: 1
        $x_1_3 = "offerWindow" ascii //weight: 1
        $x_1_4 = "component/offerscreen.xaml" ascii //weight: 1
        $x_1_5 = "PopupSleep5" ascii //weight: 1
        $x_1_6 = "BLBeacon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_MSIL_MediaArena_363871_2
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:MSIL/MediaArena"
        threat_id = "363871"
        type = "BrowserModifier"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MediaArena"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ConvertMate" ascii //weight: 1
        $x_1_2 = "Briefme.mp4" ascii //weight: 1
        $x_1_3 = "c_h_r_o_m_e_._e_x_e" ascii //weight: 1
        $x_1_4 = "ConvertMate.pdb" ascii //weight: 1
        $x_1_5 = "climatcon.com" ascii //weight: 1
        $n_100_6 = "Uninst.exe" ascii //weight: -100
        $n_100_7 = "Uninstall.exe" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule BrowserModifier_MSIL_MediaArena_363871_3
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:MSIL/MediaArena"
        threat_id = "363871"
        type = "BrowserModifier"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MediaArena"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_AppName" ascii //weight: 1
        $x_1_2 = "get_TargetPath" ascii //weight: 1
        $x_1_3 = "set_TargetPath" ascii //weight: 1
        $x_1_4 = "get_Url" ascii //weight: 1
        $x_1_5 = "get_DoBro" ascii //weight: 1
        $x_1_6 = "set_SourceIden" ascii //weight: 1
        $x_1_7 = "offer_id" ascii //weight: 1
        $x_1_8 = "PDFSkills" ascii //weight: 1
        $x_1_9 = "favicon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_MSIL_MediaArena_363871_4
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:MSIL/MediaArena"
        threat_id = "363871"
        type = "BrowserModifier"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MediaArena"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OpenFF" ascii //weight: 1
        $x_1_2 = "get_PRF_URL" ascii //weight: 1
        $x_1_3 = "get_applicationInfo" ascii //weight: 1
        $x_1_4 = "conclie.com" ascii //weight: 1
        $x_1_5 = "PDF Master" ascii //weight: 1
        $x_1_6 = "MasterAnimation.mp4" ascii //weight: 1
        $x_1_7 = "ConvertMaster.exe" ascii //weight: 1
        $n_100_8 = "Uninst.exe" ascii //weight: -100
        $n_100_9 = "Uninstall.exe" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule BrowserModifier_MSIL_MediaArena_363871_5
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:MSIL/MediaArena"
        threat_id = "363871"
        type = "BrowserModifier"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MediaArena"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "search engine" ascii //weight: 1
        $x_1_2 = "get_BrowserType" ascii //weight: 1
        $x_1_3 = "OptionalOfferWindow" ascii //weight: 1
        $x_1_4 = "isOptionalOfferSelected" ascii //weight: 1
        $x_1_5 = "get_SearchEngineUrl" ascii //weight: 1
        $x_1_6 = "AddSearchEngineToEdge" ascii //weight: 1
        $x_1_7 = "ChangeSearchEngine" ascii //weight: 1
        $x_1_8 = "PDFConvert.exe" ascii //weight: 1
        $x_1_9 = "nogosearch.com" ascii //weight: 1
        $x_1_10 = "wisewebsearch.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_MSIL_MediaArena_363871_6
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:MSIL/MediaArena"
        threat_id = "363871"
        type = "BrowserModifier"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MediaArena"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EdUp.WD.exe" ascii //weight: 1
        $x_1_2 = "Edate.exe" ascii //weight: 1
        $x_1_3 = "PDFSuperHero" ascii //weight: 1
        $x_1_4 = "install.onlinepdf-converter" ascii //weight: 1
        $x_1_5 = "edge://settings/searchEngines" ascii //weight: 1
        $x_1_6 = "default_search_provider_data" ascii //weight: 1
        $x_1_7 = "defaultsearchdomainvalue" ascii //weight: 1
        $x_1_8 = "Exception in PayloadUtils.DefaultBrowserDetails(): {1}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_MSIL_MediaArena_363871_7
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:MSIL/MediaArena"
        threat_id = "363871"
        type = "BrowserModifier"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MediaArena"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SimKstok" ascii //weight: 1
        $x_1_2 = "Default browser" ascii //weight: 1
        $x_1_3 = "edge://settings/searchEngines" ascii //weight: 1
        $x_1_4 = "Step 4 : Paste settings url in ed ed://settings/searchEngines" ascii //weight: 1
        $x_1_5 = ":{0}:Exception {1}" ascii //weight: 1
        $x_1_6 = "Step 4 : type in settings url in ed ed://settings/searchEngines" ascii //weight: 1
        $x_1_7 = "Step 5 : settings opened" ascii //weight: 1
        $x_1_8 = "Step 6 : moved to search" ascii //weight: 1
        $x_1_9 = "Step 7 : Paste search product" ascii //weight: 1
        $x_1_10 = "Step 7 : type in search product" ascii //weight: 1
        $x_1_11 = "Step 8 : changed the search engine" ascii //weight: 1
        $x_1_12 = "Step 9 : Gracefully closed edge" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_MSIL_MediaArena_363871_8
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:MSIL/MediaArena"
        threat_id = "363871"
        type = "BrowserModifier"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MediaArena"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "com/nav?string_interpolation=GET_OSOU&appId=" wide //weight: 3
        $x_3_2 = "we will update is_sp_set = true !!" wide //weight: 3
        $x_3_3 = "to disable Bing popup ..." wide //weight: 3
        $x_3_4 = "SO_declined" wide //weight: 3
        $x_2_5 = "Eating key stroke" wide //weight: 2
        $x_1_6 = "GET_IS_MONETIZE" wide //weight: 1
        $x_1_7 = "thankyou?tyid=" wide //weight: 1
        $x_1_8 = "TYP_opened" wide //weight: 1
        $x_1_9 = "default browser change is sent to monetiz" wide //weight: 1
        $x_1_10 = "GetEdgeProcWindow -- MsEdge process" wide //weight: 1
        $x_1_11 = "reading 'default_search_provider_data' failure" wide //weight: 1
        $x_1_12 = "advertisements based on your searches" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_3_*) and 6 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_3_*) and 3 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_MSIL_MediaArena_365687_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:MSIL/MediaArena!MTB"
        threat_id = "365687"
        type = "BrowserModifier"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MediaArena"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_Show" ascii //weight: 1
        $x_1_2 = "OptionalOffer" ascii //weight: 1
        $x_1_3 = "InstallFreePDF" ascii //weight: 1
        $x_1_4 = "get_BrowserType" ascii //weight: 1
        $x_1_5 = "DefaultSearchEngine" ascii //weight: 1
        $x_1_6 = "FreePDFPlusInst" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_MSIL_MediaArena_365687_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:MSIL/MediaArena!MTB"
        threat_id = "365687"
        type = "BrowserModifier"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MediaArena"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "searchEngine" ascii //weight: 1
        $x_1_2 = "search offer" ascii //weight: 1
        $x_1_3 = "Default browser" ascii //weight: 1
        $x_1_4 = "Searchvibesnow" ascii //weight: 1
        $x_1_5 = "PDFSuperHero.exe" ascii //weight: 1
        $x_1_6 = "edge://settings/searchEngines" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_MSIL_MediaArena_365687_2
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:MSIL/MediaArena!MTB"
        threat_id = "365687"
        type = "BrowserModifier"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MediaArena"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OfferScreen" ascii //weight: 1
        $x_1_2 = "offerWindow" ascii //weight: 1
        $x_1_3 = "offerscreen.xaml" ascii //weight: 1
        $x_1_4 = "DefBrowser" ascii //weight: 1
        $x_1_5 = "BrowserDoneLoadedWithUrl" ascii //weight: 1
        $x_1_6 = "default_search_provider_data" ascii //weight: 1
        $x_1_7 = "get_AppSettings" ascii //weight: 1
        $x_1_8 = "ChangeSrhcBox" ascii //weight: 1
        $x_1_9 = "PDF Central" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_MSIL_MediaArena_365687_3
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:MSIL/MediaArena!MTB"
        threat_id = "365687"
        type = "BrowserModifier"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MediaArena"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OfferScreen" ascii //weight: 1
        $x_1_2 = "offerWindow" ascii //weight: 1
        $x_1_3 = "IDS_DEFAULT_BROWSER" ascii //weight: 1
        $x_1_4 = "IDS_DEFAULT_SEARCH_PROVIDER_DATA" ascii //weight: 1
        $x_1_5 = "IDS_IS_INSTALL_ACCEPTED" ascii //weight: 1
        $x_1_6 = "browser_loading_time_url" ascii //weight: 1
        $x_1_7 = "get_AppSettings" ascii //weight: 1
        $x_1_8 = "change search settings" ascii //weight: 1
        $x_1_9 = "PdfManager" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_MSIL_MediaArena_365687_4
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:MSIL/MediaArena!MTB"
        threat_id = "365687"
        type = "BrowserModifier"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MediaArena"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OfferScreen" ascii //weight: 1
        $x_1_2 = "offerWindow" ascii //weight: 1
        $x_1_3 = "DefBrowser" ascii //weight: 1
        $x_1_4 = "IDS_DOWNLOAD_BROWSER" ascii //weight: 1
        $x_1_5 = "IDS_DEFAULT_BROWSER" ascii //weight: 1
        $x_1_6 = "IDS_EDGE_SETTINGS_DEF_BROWSER" ascii //weight: 1
        $x_1_7 = "BrowserLoadedWithUrl" ascii //weight: 1
        $x_1_8 = "COLLECT_DATA_SEARCH_ENGINE" ascii //weight: 1
        $n_100_9 = "Uninst.exe" ascii //weight: -100
        $n_100_10 = "Uninstall.exe" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

