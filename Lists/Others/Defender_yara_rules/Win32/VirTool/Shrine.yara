rule VirTool_Win32_Shrine_A_2147758089_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Shrine.A"
        threat_id = "2147758089"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Shrine"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "syscall.LazyDLL" ascii //weight: 1
        $x_1_2 = "LazyDLL).NewProc" ascii //weight: 1
        $x_1_3 = "brimstone/go-shellcode.Run" ascii //weight: 1
        $x_1_4 = "brimstone/go-shellcode.VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

