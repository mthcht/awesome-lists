rule Trojan_Win32_Cometer_SM_2147773498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cometer.SM!MSR"
        threat_id = "2147773498"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cometer"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 94 85 0c fe ff ff 0f b6 41 fc c0 e2 02 0f b6 84 85 0c fe ff ff c0 e8 04 0a d0 88 57 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

