rule VirTool_Win64_Gepesz_A_2147969782_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Gepesz.A"
        threat_id = "2147969782"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Gepesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8b 4a 24 49 03 c8 42 0f b7 14 49 41 8b 4a 1c 49 03 c8 8b 04 91 ?? ?? ?? ?? ?? ?? ?? 49 03 c0 49 8b cc ff ?? 48 8b 54 24 30 48 83 c9 ff 48 8b 12 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8b ca 83 c9 20 41 80 fb 19 45 8a 1e 0f 47 ca 49 ff c6 33 ce 69 f1 ?? ?? ?? ?? 45 84 db ?? ?? 81 fe ?? ?? ?? ?? ?? ?? 45 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

