rule VirTool_Win32_ChromeKey_A_2147901292_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/ChromeKey.A"
        threat_id = "2147901292"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ChromeKey"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "find end of encrypted_key" ascii //weight: 1
        $x_1_2 = "findKeyFiles" ascii //weight: 1
        $x_2_3 = "Base64 key for" ascii //weight: 2
        $x_1_4 = "Chrome" ascii //weight: 1
        $x_2_5 = "Decoded key" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

