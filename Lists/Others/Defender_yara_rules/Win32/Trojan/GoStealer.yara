rule Trojan_Win32_GoStealer_DC_2147934013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GoStealer.DC!MTB"
        threat_id = "2147934013"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "54"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "Google Chrome Credit Cards" ascii //weight: 50
        $x_1_2 = "Login Data" ascii //weight: 1
        $x_1_3 = "Application Data" ascii //weight: 1
        $x_1_4 = "User Data" ascii //weight: 1
        $x_1_5 = "encrypted_key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

