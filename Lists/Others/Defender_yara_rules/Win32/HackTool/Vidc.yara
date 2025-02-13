rule HackTool_Win32_Vidc_2147602081_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Vidc"
        threat_id = "2147602081"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidc"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "34"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "vIDC2" ascii //weight: 10
        $x_10_2 = "vIDC-server" ascii //weight: 10
        $x_10_3 = "Server: YYProxy" ascii //weight: 10
        $x_1_4 = "[vidcs] - port=%d,auth=%s enabled=%s" ascii //weight: 1
        $x_1_5 = "[mtcpr] - failed to mapping %s --> %d,ret=%d" ascii //weight: 1
        $x_1_6 = "- the program(%s) has been runned,PID=0x%x!" ascii //weight: 1
        $x_1_7 = "[mtcpl] - failed to start MportTCP,ret=%d!" ascii //weight: 1
        $x_1_8 = "Tunnel-UDP has been started, port=%d!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

