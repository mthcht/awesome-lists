rule BrowserModifier_Win32_MegaSearch_15989_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/MegaSearch"
        threat_id = "15989"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "MegaSearch"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "34"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "{8BC6346B-FFB0-4435-ACE3-FACA6CD77816}" ascii //weight: 20
        $x_5_2 = "SearchAssistant" ascii //weight: 5
        $x_5_3 = "MegaHost" ascii //weight: 5
        $x_2_4 = "RpcStringFreeA" ascii //weight: 2
        $x_1_5 = "URLDownloadToCacheFileA" ascii //weight: 1
        $x_1_6 = "CreateProcessA" ascii //weight: 1
        $x_1_7 = "execUrl" ascii //weight: 1
        $x_1_8 = "CoCreateGuid" ascii //weight: 1
        $x_1_9 = "UuidToStringA" ascii //weight: 1
        $x_1_10 = "CreateFileA" ascii //weight: 1
        $x_1_11 = "WritePrivateProfileStringA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_5_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_5_*) and 4 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_5_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_MegaSearch_15989_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/MegaSearch"
        threat_id = "15989"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "MegaSearch"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "MegaHost.dll" ascii //weight: 5
        $x_5_2 = "http://69.50.164.11/v1/mh.php?pid=%s&cid=%s&p=%s&t=%s&vh=%i&vt=%i" ascii //weight: 5
        $x_5_3 = "http://best-search.us" ascii //weight: 5
        $x_5_4 = "MegaTlbr.dll" ascii //weight: 5
        $x_1_5 = "Software\\Microsoft\\Internet Explorer\\Main" ascii //weight: 1
        $x_1_6 = "URLDownloadToCacheFileA" ascii //weight: 1
        $x_1_7 = "DeleteUrlCacheEntry" ascii //weight: 1
        $x_1_8 = "GetUrlCacheEntryInfoA" ascii //weight: 1
        $x_1_9 = "SearchAssistant" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

