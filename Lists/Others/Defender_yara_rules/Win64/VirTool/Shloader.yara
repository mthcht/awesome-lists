rule VirTool_Win64_Shloader_A_2147927350_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Shloader.A"
        threat_id = "2147927350"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Shloader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 0d 1a 15 00 00 48 89 15 17 15 00 00 c3}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b c1 4c 8b d0 8b 05 06 15 00 00 ff 25 04 15 00 00 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

