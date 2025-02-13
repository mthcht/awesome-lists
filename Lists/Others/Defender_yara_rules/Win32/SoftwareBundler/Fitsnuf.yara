rule SoftwareBundler_Win32_Fitsnuf_234449_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Fitsnuf"
        threat_id = "234449"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Fitsnuf"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "http://unstiff.pw" ascii //weight: 10
        $x_1_2 = "WajIEnhance" ascii //weight: 1
        $x_1_3 = "social2search.exe" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\yessearchesSoftware" ascii //weight: 1
        $x_1_5 = "yessearcheshp" ascii //weight: 1
        $x_1_6 = "\\stub_youndoo.exe" ascii //weight: 1
        $x_1_7 = "SOFTWARE\\youndooSoftware" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

