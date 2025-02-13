rule SoftwareBundler_Win32_Techrelinst_233874_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Techrelinst"
        threat_id = "233874"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Techrelinst"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Install Your Updater the default directory." ascii //weight: 1
        $x_1_2 = "Install Open Download Manager to the default directory." ascii //weight: 1
        $x_10_3 = "Open http://www.Social2Search.com/privacy" ascii //weight: 10
        $x_10_4 = "enable Social2Search for all browsers." ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

