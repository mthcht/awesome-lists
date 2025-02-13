rule VirTool_Win32_AvetDllInject_G_2147742904_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/AvetDllInject.G!MTB"
        threat_id = "2147742904"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AvetDllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "libgcj-16.dll" ascii //weight: 2
        $x_2_2 = {65 78 65 63 5f 63 61 6c 63 [0-2] 2e 64 6c 6c}  //weight: 2, accuracy: Low
        $x_2_3 = "WINDOWS\\system32\\cmd.exe" ascii //weight: 2
        $x_2_4 = {00 00 b8 01 00 00 00 03 00 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

