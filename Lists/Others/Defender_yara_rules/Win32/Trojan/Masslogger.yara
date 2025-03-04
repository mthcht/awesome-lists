rule Trojan_Win32_MassLogger_A_2147758691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MassLogger.A!MTB"
        threat_id = "2147758691"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MassLogger Exit after delivery:" ascii //weight: 1
        $x_1_2 = "MassLogger Process:" ascii //weight: 1
        $x_1_3 = "MassLogger Started:" ascii //weight: 1
        $x_1_4 = "Logger Details" ascii //weight: 1
        $x_1_5 = "Keylogger And Clipboard" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

