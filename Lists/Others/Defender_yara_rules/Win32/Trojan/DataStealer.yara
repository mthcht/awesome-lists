rule Trojan_Win32_DataStealer_VD_2147761106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DataStealer.VD!MTB"
        threat_id = "2147761106"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DataStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c2 83 e0 [0-64] 8a 45 ?? 34 ?? 88 45 ?? 03 11 8a 45 ?? 88 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

