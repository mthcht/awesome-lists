rule BrowserModifier_Win32_Procesemes_B_140688_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Procesemes.B"
        threat_id = "140688"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Procesemes"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LoadResource" ascii //weight: 1
        $x_1_2 = "DllCanUnloadNow" ascii //weight: 1
        $x_1_3 = "HttpOpenRequestW" ascii //weight: 1
        $x_1_4 = "Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 5.0; .NET CLR 1.0.2914)" wide //weight: 1
        $x_1_5 = "InternetSetCookieW" ascii //weight: 1
        $x_1_6 = {8b d7 83 e2 01 c1 e2 02 6a 04 59 2b ca d2 e0 08 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Procesemes_C_140689_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Procesemes.C"
        threat_id = "140689"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Procesemes"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "Wrong security code" wide //weight: 10
        $x_10_2 = "%%name_file_02%%" ascii //weight: 10
        $x_10_3 = {50 00 4e 00 47 00 00 00 [0-15] 2e 00 64 00 6c 00 6c}  //weight: 10, accuracy: Low
        $x_1_4 = "onlyxpornvideo.com" wide //weight: 1
        $x_1_5 = "bestxxxvideo4free.com" wide //weight: 1
        $x_1_6 = "onlinesexzone.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

