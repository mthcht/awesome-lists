rule VirTool_Win64_LibSys_A_2147956704_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/LibSys.A"
        threat_id = "2147956704"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "LibSys"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 31 db 4d 31 d2 49 89 cb 49 89 d2 c3}  //weight: 1, accuracy: High
        $x_1_2 = {41 52 48 31 c0 49 89 ca 44 89 d8 c3}  //weight: 1, accuracy: High
        $x_1_3 = {0f b7 45 ee 48 8b 55 18 48 01 d0 0f b6 00 3c e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

