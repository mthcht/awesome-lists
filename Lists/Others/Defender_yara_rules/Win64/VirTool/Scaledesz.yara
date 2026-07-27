rule VirTool_Win64_Scaledesz_A_2147974558_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Scaledesz.A"
        threat_id = "2147974558"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Scaledesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 c7 00 ff ff ff ff 48 8b 8c 24 ?? 01 00 00 48 89 48 08 48 8b 8c 24 ?? 01 00 00 48 89 48 10 48 c7 40 18 20 00 00 00 48 8b 8c 24 ?? 01 00 00 48 89 48 20}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 48 08 48 c7 40 10 00 30 00 00 48 c7 40 18 40 00 00 00 48 89 c3 b9 04 00 00 00 48 89 cf 48 8b 84 24 ?? ?? 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

