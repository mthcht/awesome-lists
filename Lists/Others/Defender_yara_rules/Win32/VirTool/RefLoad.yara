rule VirTool_Win32_RefLoad_A_2147940946_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/RefLoad.A"
        threat_id = "2147940946"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "RefLoad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {4d 5a e8 00 00 00 00 5b 52 45 55 8b ec 81 c3 ?? ?? ?? ?? ff d3 c9 c3}  //weight: 5, accuracy: Low
        $x_1_2 = {5b bc 4a 6a}  //weight: 1, accuracy: High
        $x_1_3 = {5d 68 fa 3c}  //weight: 1, accuracy: High
        $x_1_4 = {8e 4e 0e ec}  //weight: 1, accuracy: High
        $x_1_5 = {aa fc 0d 7c}  //weight: 1, accuracy: High
        $x_1_6 = {1b c6 46 79}  //weight: 1, accuracy: High
        $x_1_7 = {b8 0a 4c 53}  //weight: 1, accuracy: High
        $x_1_8 = {54 ca af 91}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

