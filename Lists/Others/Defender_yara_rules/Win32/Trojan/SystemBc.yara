rule Trojan_Win32_SystemBc_YAC_2147896605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SystemBc.YAC!MTB"
        threat_id = "2147896605"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SystemBc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 cc 03 55 ac 03 55 e8 2b d0 8b 45 d8 31 10 83 45 ?? 04 83 45 d8 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

