rule VirTool_Win32_MaleficAms_A_2147947872_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/MaleficAms.A"
        threat_id = "2147947872"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "MaleficAms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "::FromBase64String($" wide //weight: 1
        $x_1_2 = ".Webclient" wide //weight: 1
        $x_1_3 = ".GetString($" wide //weight: 1
        $x_1_4 = ".DownloadString($" wide //weight: 1
        $x_1_5 = "iex" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

