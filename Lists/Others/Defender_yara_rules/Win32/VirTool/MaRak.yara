rule VirTool_Win32_MaRak_A_2147927743_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/MaRak.A"
        threat_id = "2147927743"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "MaRak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CurrentDomain.DefineDynamicAssembly(4, 1)" wide //weight: 1
        $x_1_2 = "DefineDynamicModule(2, $False).DefineType(0)" wide //weight: 1
        $x_1_3 = "DefinePInvokeMethod('GetStdHandle" wide //weight: 1
        $x_1_4 = "SetImplementationFlags(128)" wide //weight: 1
        $x_1_5 = "DefinePInvokeMethod('SetConsoleMode" wide //weight: 1
        $x_1_6 = "GetStdHandle(-10), 0x0080" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

