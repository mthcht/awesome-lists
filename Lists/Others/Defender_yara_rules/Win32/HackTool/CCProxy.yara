rule HackTool_Win32_CCProxy_2147621705_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/CCProxy"
        threat_id = "2147621705"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CCProxy"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "Server: CCProxy" ascii //weight: 2
        $x_2_2 = "function FindProxyForURL(url, host)" ascii //weight: 2
        $x_2_3 = {50 72 6f 78 79 2d 61 67 65 6e 74 3a 20 (77 6f 72 6b 73|43 43 50 72 6f)}  //weight: 2, accuracy: Low
        $x_1_4 = "WorksNT Stop Start" ascii //weight: 1
        $x_1_5 = "Youngzsoft Game Proxy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_CCProxy_B_2147655504_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/CCProxy.B"
        threat_id = "2147655504"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CCProxy"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Server: CCProxy" ascii //weight: 1
        $x_1_2 = {50 72 6f 78 79 2d 61 67 65 6e 74 3a 20 (77 6f 72 6b 73|43 43 50 72 6f)}  //weight: 1, accuracy: Low
        $x_1_3 = "remotecontrol" ascii //weight: 1
        $x_1_4 = "proxy.txt" ascii //weight: 1
        $x_1_5 = {43 43 50 72 6f 78 79 00 5c 5c 2e 5c 6d 61 69 6c 73 6c 6f 74 5c 25 73 00 2d 72 65 73 65 74 00 00 2d 75 70 64 61 74 65 00 2d 73 65 72 76 69 63 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

