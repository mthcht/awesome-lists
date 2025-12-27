rule VirTool_Win64_SearchMZMarker_A_2147955407_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/SearchMZMarker.A"
        threat_id = "2147955407"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "SearchMZMarker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d 04 0a 49 3b c0 7d 25 b8 4d 5a 00 00 66 39 01 75 0c 81 b9 fc 03 00 00 f4 f4 f4 f4 74 12 48 ff c1 48 8d 04 0a 48 3d 00 10 00 00 7c d2 33 c0 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

