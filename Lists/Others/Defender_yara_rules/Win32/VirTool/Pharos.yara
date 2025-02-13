rule VirTool_Win32_Pharos_A_2147762340_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Pharos.A"
        threat_id = "2147762340"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Pharos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 04 8b 4c 24 2c 89 08 8b 4c 24 20 89 48 04 c7 40 08 40 00 00 00 8b 4c 24 28 89 48 0c 8b 0d 4c ed 54 00 89 0c 24 89 44 24 04 c7 44 24 08 04 00 00 00 c7 44 24 0c 04 00 00 00 e8 ?? ?? ?? ?? 8b 44 24 10 85 c0 ?? ?? 8b 54 24 24 8b 02 ff ?? 83 c4 ?? c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

