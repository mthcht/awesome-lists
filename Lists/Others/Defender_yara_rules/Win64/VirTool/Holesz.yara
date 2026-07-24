rule VirTool_Win64_Holesz_A_2147974407_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Holesz.A"
        threat_id = "2147974407"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Holesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 84 24 68 01 00 00 48 89 bc 24 80 01 00 00 c6 44 24 57 00 44 0f 11 7c 24 68 ?? ?? ?? ?? ?? 44 0f 11 3a 44 0f 11 7a 10 31 c0 31 db ?? ?? ?? ?? ?? ?? ?? bf 08 00 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {55 48 89 e5 48 81 ec 98 00 00 00 48 89 84 24 a8 00 00 00 48 89 8c 24 b8 00 00 00 48 89 5c 24 70 48 89 44 24 68 48 89 bc 24 80 00 00 00 48 89 4c 24 78 48 c7 84 24 ?? 00 00 00 08 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

