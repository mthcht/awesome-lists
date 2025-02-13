rule BrowserModifier_Win32_GonnaSearch_14853_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/GonnaSearch"
        threat_id = "14853"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "GonnaSearch"
        severity = "21"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\SearchAddon" ascii //weight: 1
        $x_1_2 = "http://www.blazehits.net/popup." ascii //weight: 1
        $x_1_3 = {53 65 61 72 63 68 41 64 64 6f 6e 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
        $x_1_4 = ".sprinks.com" ascii //weight: 1
        $x_1_5 = "www.yandex.ru/yandsearch" ascii //weight: 1
        $x_1_6 = {2e 66 69 6e 64 77 68 61 74 2e 00 00 4b 65 79 77 6f 72 64 73 3d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

