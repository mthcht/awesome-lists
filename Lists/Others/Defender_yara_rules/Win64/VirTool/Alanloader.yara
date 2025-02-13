rule VirTool_Win64_Alanloader_A_2147832002_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Alanloader.A"
        threat_id = "2147832002"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Alanloader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 33 db ac 84 c0 ?? ?? c1 cf 13 3c 61 48 0f 4d da 2a c3 48 0f b6 c0 03 f8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 0f b7 0b 48 03 f9 fd 48 33 c0 b0 5c 48 8b f7 f2 ae fc ?? ?? ?? 48 83 c7 02 48 2b f7 48 8b d6 48 8b cf}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 36 48 03 34 24 48 33 c0 48 8b fe b9 12 05 00 00 fc f2 ae 48 2b fe 48 ff cf 48 8b ce 48 8b d7}  //weight: 1, accuracy: High
        $x_1_4 = {49 c7 c1 04 00 00 00 49 c7 c0 00 30 00 00 49 8b d7 48 33 c9 48 83 ec 28 ff d0 48 83 c4 28 48 85 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

