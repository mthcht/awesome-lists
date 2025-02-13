rule Misleading_Win32_Nowferine_240741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:Win32/Nowferine"
        threat_id = "240741"
        type = "Misleading"
        platform = "Win32: Windows 32-bit platform"
        family = "Nowferine"
        severity = "7"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://www.winferno.com/re/support.asp" wide //weight: 1
        $x_1_2 = "Winferno Registry Power Cleaner" wide //weight: 1
        $x_1_3 = "RegPowerCleanMutex" wide //weight: 1
        $x_1_4 = "Software\\Winferno\\RegPowerClean" wide //weight: 1
        $x_1_5 = "dontcorrectmeimtheking" wide //weight: 1
        $x_1_6 = "registry-scanning-overviewcontents.htm" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

