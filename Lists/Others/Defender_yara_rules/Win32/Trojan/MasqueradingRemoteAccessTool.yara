rule Trojan_Win32_MasqueradingRemoteAccessTool_A_2147768065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MasqueradingRemoteAccessTool.A"
        threat_id = "2147768065"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MasqueradingRemoteAccessTool"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

