rule Trojan_Win32_SuspNetworkConfig_A_2147955553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspNetworkConfig.A"
        threat_id = "2147955553"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspNetworkConfig"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "curl.exe " ascii //weight: 1
        $x_1_2 = ".com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

