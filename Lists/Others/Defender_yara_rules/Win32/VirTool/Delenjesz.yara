rule VirTool_Win32_Delenjesz_A_2147977307_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Delenjesz.A"
        threat_id = "2147977307"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Delenjesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 ?? ?? ?? ?? ?? ?? ?? 50 6a 00 56 89 45 08 ff ?? ?? ?? ?? ?? 8b f8 85 ff ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 ff 75 08 53 57 56 ff ?? ?? ?? ?? ?? 85 c0 ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 00 6a 00 57 50 6a 00 6a 00 56 ff ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

