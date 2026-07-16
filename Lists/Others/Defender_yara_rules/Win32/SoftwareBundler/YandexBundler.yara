rule SoftwareBundler_Win32_YandexBundler_490227_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/YandexBundler.muthu66"
        threat_id = "490227"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "YandexBundler"
        severity = "High"
        info = "muthu66: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ChromeSetup.exe" ascii //weight: 1
        $x_1_2 = "uTorrent.exe" ascii //weight: 1
        $x_2_3 = "YandexPackLoader.exe" ascii //weight: 2
        $x_2_4 = "\\Yandex.exe\" /silent" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

