rule VirTool_Win32_SuspMailInFileDiscovery_A_2147957701_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspMailInFileDiscovery.A"
        threat_id = "2147957701"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspMailInFileDiscovery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd" wide //weight: 1
        $x_1_2 = "/c dir /b /s .ost" wide //weight: 1
        $x_1_3 = "| findstr /e .ost" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_SuspMailInFileDiscovery_B_2147957702_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspMailInFileDiscovery.B"
        threat_id = "2147957702"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspMailInFileDiscovery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd" wide //weight: 1
        $x_1_2 = "/c dir /b /s .pst" wide //weight: 1
        $x_1_3 = "| findstr /e .pst" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

