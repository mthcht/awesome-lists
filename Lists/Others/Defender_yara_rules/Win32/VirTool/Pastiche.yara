rule VirTool_Win32_Pastiche_A_2147757120_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Pastiche.A"
        threat_id = "2147757120"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Pastiche"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 05 0d 51 00 00 48 33 c4 48 89 44 24 40 48 ?? ?? ?? ?? 4c 8b c1 48 89 44 24 28 4c 8d ?? ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 48 c7 44 24 20 00 00 00 00 48 8d ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 85 c0 75 42 48 8b 4c 24 30}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 5c 24 50 ff ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? 8b d8 ff ?? ?? ?? ?? ?? 85 db 48 8b 5c 24 50 75 17 48 8b 44 24 38 48 8b 4c 24 40 48 33 cc e8 ?? ?? ?? ?? 48 83 c4 58 c3}  //weight: 1, accuracy: Low
        $x_1_3 = "\\pipe\\spoolss" ascii //weight: 1
        $x_1_4 = "ncacn_np" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

