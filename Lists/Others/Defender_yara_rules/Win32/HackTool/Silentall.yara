rule HackTool_Win32_Silentall_2147854445_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Silentall"
        threat_id = "2147854445"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Silentall"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SilentAll.Net Kat" wide //weight: 1
        $x_1_2 = "SilentALLSampleProject.Properties" ascii //weight: 1
        $x_1_3 = "uTorrent" wide //weight: 1
        $x_1_4 = "BitTorrent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

