rule SoftwareBundler_Win32_YourSiteBar_15049_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/YourSiteBar"
        threat_id = "15049"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "YourSiteBar"
        severity = "16"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "/aid:%i /cfg:%s /soft:%i /vkey:%s /tkey:%s /tlock:%s /exe:%s" ascii //weight: 5
        $x_2_2 = "%s\\n_%s.exe" ascii //weight: 2
        $x_3_3 = "%s?aid=%i&cfg=%s&vkey=%s" ascii //weight: 3
        $x_3_4 = "ysb_m" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

