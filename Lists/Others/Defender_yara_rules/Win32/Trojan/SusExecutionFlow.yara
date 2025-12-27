rule Trojan_Win32_SusExecutionFlow_A_2147958184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusExecutionFlow.A"
        threat_id = "2147958184"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusExecutionFlow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c dir" ascii //weight: 1
        $x_1_2 = "mkdir" ascii //weight: 1
        $x_1_3 = "kworking" ascii //weight: 1
        $x_1_4 = ".exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

