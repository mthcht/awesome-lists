rule VirTool_Win32_Gatvm_2147684534_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Gatvm"
        threat_id = "2147684534"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Gatvm"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 74 24 28 fc 07 00 9c 60 68 ?? ?? ?? ?? ?? ?? ?? ?? ?? bf ?? ?? ?? ?? 03 34 24 8a (0e|06) 0f b6 (c1|c0) (8d|46) ff 34 85 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

