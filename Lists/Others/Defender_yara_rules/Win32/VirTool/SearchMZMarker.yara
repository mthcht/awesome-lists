rule VirTool_Win32_SearchMZMarker_A_2147955408_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SearchMZMarker.A"
        threat_id = "2147955408"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SearchMZMarker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3b ce 7d 23 8d 04 11 bf 4d 5a 00 00 66 39 38 75 0d 81 bc 11 fc 03 00 00 f4 f4 f4 f4 74 0b 41 81 f9 00 10 00 00 7c d9 33 c0 5f 5e c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

