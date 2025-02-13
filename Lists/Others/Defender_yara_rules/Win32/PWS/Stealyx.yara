rule PWS_Win32_Stealyx_A_2147650374_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Stealyx.A"
        threat_id = "2147650374"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealyx"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VUhKdlozSmhiU0JHYVd4bGMxeFhiM0pzWkNCdlppQlhZWEpqY21GbWRGeERZV05vWlZ4WFJFST0=" wide //weight: 1
        $x_1_2 = "WEVGd2NHeGxJRU52YlhCMWRHVnlYRk5oWm1GeWFWeERZV05vWlM1a1lnPT0=" wide //weight: 1
        $x_1_3 = "WEVkdmIyZHNaVnhEYUhKdmJXVmNWWE5sY2lCRVlYUmhYRVJsWm1GMWJIUmNWMlZpSUVSaGRHRT0=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

