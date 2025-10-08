rule Trojan_Win32_SusNetworkConfig_A_2147954088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusNetworkConfig.A"
        threat_id = "2147954088"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusNetworkConfig"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "curl.exe " ascii //weight: 1
        $x_1_2 = ".com" wide //weight: 1
        $n_1_3 = "9453e881-26a8-4973-ba2e-76269e901d0w" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

