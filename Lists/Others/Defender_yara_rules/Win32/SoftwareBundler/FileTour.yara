rule SoftwareBundler_Win32_FileTour_222749_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/FileTour"
        threat_id = "222749"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "FileTour"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Evgen Kugitko" ascii //weight: 2
        $x_1_2 = "2e746f7272656e74" ascii //weight: 1
        $x_1_3 = "horses.file-tour.ru" ascii //weight: 1
        $x_1_4 = "http://%s/v_install?sid=16045&start=1&guid=$__GUID&sig=$__SIG&ovr=$__OVR&browser=$__BROWSER&label=%s&aux=%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

