rule VirTool_Win32_SwifGenerator_A_2147608162_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SwifGenerator.A"
        threat_id = "2147608162"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SwifGenerator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "80"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "C:\\Program Files\\vb6mini\\VB6.OLB" ascii //weight: 5
        $x_2_2 = "EVENT_SINK_QueryInterface" ascii //weight: 2
        $x_10_3 = "http://www.0x4f.cn/blog" wide //weight: 10
        $x_2_4 = "MZKERNEL32.DLL" ascii //weight: 2
        $x_2_5 = "Form1" ascii //weight: 2
        $x_10_6 = "VB5!6&vb6chs.dll" ascii //weight: 10
        $x_2_7 = "VarFileInfo" wide //weight: 2
        $x_2_8 = "Click" ascii //weight: 2
        $x_5_9 = "VBA6.DLL" ascii //weight: 5
        $x_10_10 = "FLASH" wide //weight: 10
        $x_10_11 = "Flash 0day.exe" wide //weight: 10
        $x_10_12 = "Win 9,0,115,0ie.swf" wide //weight: 10
        $x_10_13 = "MethCallEngine" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

