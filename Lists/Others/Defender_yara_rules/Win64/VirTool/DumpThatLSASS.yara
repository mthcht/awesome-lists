rule VirTool_Win64_DumpThatLSASS_A_2147911230_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/DumpThatLSASS.A!MTB"
        threat_id = "2147911230"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "DumpThatLSASS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {48 8b cf ff 15 b4 53 01 00 4c 89 74 24 30 41 b9 ?? 00 00 00 8b d0 4c 89 74 24 28 4c 8b c6 4c 89 74 24 20 48 8b cf ff 15 e1 55 01}  //weight: 4, accuracy: Low
        $x_3_2 = {8a 01 3a 04 11 75 0c 48 ff c1 49 ff c8 75 f1 48 33 c0 c3}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

