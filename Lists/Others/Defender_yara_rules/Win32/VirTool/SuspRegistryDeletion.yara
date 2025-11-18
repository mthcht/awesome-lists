rule VirTool_Win32_SuspRegistryDeletion_A_2147957698_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspRegistryDeletion.A"
        threat_id = "2147957698"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRegistryDeletion"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\INTERNET SETTINGS\\ZONEMAP" wide //weight: 1
        $x_1_2 = " /v " wide //weight: 1
        $x_1_3 = "PROXYBYPASS" wide //weight: 1
        $x_1_4 = "reg" wide //weight: 1
        $x_1_5 = " delete " wide //weight: 1
        $n_100_6 = ".bat" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

