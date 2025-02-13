rule VirTool_Win64_Casinj_A_2147927066_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Casinj.A"
        threat_id = "2147927066"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Casinj"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 83 ec 38 33 c0 45 33 c9 48 21 44 24 20 48 ba 88 88 88 88 88 88 88 88 ?? 99 99 99 99 99 99 99 99 49 b8 77 77 77 77 77 77 77 77 ?? ?? ?? ?? 48 b8 66 66 66 66 66 66 66 66 ff d0 33 c0 48 83 c4 38 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

