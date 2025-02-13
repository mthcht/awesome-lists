rule TrojanDownloader_Win32_Elsentric_AG_2147835429_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Elsentric.AG!MSR"
        threat_id = "2147835429"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Elsentric"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "/%x/ketwer90o/%02d%02d%02d%02d.html" ascii //weight: 5
        $x_5_2 = "/%x/archive/%02d%02d%02d%02d.html" ascii //weight: 5
        $x_1_3 = "Elise14" ascii //weight: 1
        $x_1_4 = "{5947BACD-63BF-4e73-95D7-0C8A98AB95F2}" ascii //weight: 1
        $x_1_5 = "runexe 1.exe" ascii //weight: 1
        $x_1_6 = "rundll 1.dll,DllMain" ascii //weight: 1
        $x_1_7 = "profiles.ini" ascii //weight: 1
        $x_1_8 = "\\prefs.js" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 6 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

