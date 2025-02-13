rule VirTool_Win32_Icenipto_A_2147624362_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Icenipto.A"
        threat_id = "2147624362"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Icenipto"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Icepoint Botnet Server Maker" ascii //weight: 1
        $x_1_2 = "prjGenerator.vbp" wide //weight: 1
        $x_1_3 = "\\YourServer.exe" wide //weight: 1
        $x_1_4 = "zombie is ready for control" wide //weight: 1
        $x_1_5 = "[ all attack stopped ]" wide //weight: 1
        $x_1_6 = "\\ddosstat.exe" wide //weight: 1
        $x_1_7 = "explorer.exe http://Botnet.8800.org" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

