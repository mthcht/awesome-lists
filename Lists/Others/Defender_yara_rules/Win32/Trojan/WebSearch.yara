rule Trojan_Win32_WebSearch_F_2147625865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WebSearch.F"
        threat_id = "2147625865"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WebSearch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = ".ru/search/searchbho.php" ascii //weight: 10
        $x_10_2 = "<!--results-->" ascii //weight: 10
        $x_10_3 = "SearchBHO.SEOBHO.1" ascii //weight: 10
        $x_1_4 = "search.yahoo.com" ascii //weight: 1
        $x_1_5 = "nova.rambler.ru" ascii //weight: 1
        $x_1_6 = "yandex.ru" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

