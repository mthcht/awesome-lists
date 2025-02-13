rule VirTool_Win32_Obfuscator_Cpuid_2147679114_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator_Cpuid"
        threat_id = "2147679114"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator_Cpuid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f a2 3d f6 06 00 00 75 ?? 81 f9 9c e1 00 00 75 ?? 81 fa ff fb eb bf 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

