rule Trojan_Win32_SusNativeAPI_A_2147958195_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusNativeAPI.A"
        threat_id = "2147958195"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusNativeAPI"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "cspipe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

