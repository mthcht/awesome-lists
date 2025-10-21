rule VirTool_Win32_Shelclick_A_2147955673_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Shelclick.A"
        threat_id = "2147955673"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Shelclick"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 68 00 00 00 66 89 ?? ?? b9 74 00 00 00 66 89 ?? ?? ba 74 00 00 00 66 89 ?? ?? b8 70 00 00 00 66 89}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 0a 88 8c ?? ?? ?? ?? ff eb ?? c6 45 ?? 2e c6 45 ?? 64 c6 45 ?? 6c c6 45 ?? 6c}  //weight: 1, accuracy: Low
        $x_1_3 = {68 8d f1 4f 84 6a ?? e8}  //weight: 1, accuracy: Low
        $x_1_4 = {68 b7 70 ad f4 6a ?? e8}  //weight: 1, accuracy: Low
        $x_1_5 = {68 ca a3 5c 8f 6a ?? e8}  //weight: 1, accuracy: Low
        $x_1_6 = {68 02 0d 58 c6 6a ?? e8}  //weight: 1, accuracy: Low
        $x_1_7 = {68 25 c1 31 1e 6a ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

