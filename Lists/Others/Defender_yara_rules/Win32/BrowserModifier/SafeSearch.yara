rule BrowserModifier_Win32_SafeSearch_10771_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/SafeSearch"
        threat_id = "10771"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "SafeSearch"
        severity = "6"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Redirect URL:" ascii //weight: 1
        $x_1_2 = "safesearch://Info/" ascii //weight: 1
        $x_1_3 = "keyword=" ascii //weight: 1
        $x_1_4 = {53 61 66 65 53 65 61 72 63 68 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
        $x_1_5 = "/search/index.html?srch=%s&pin=%s&ccinfo=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

