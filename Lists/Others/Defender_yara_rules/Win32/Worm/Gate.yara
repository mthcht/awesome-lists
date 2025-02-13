rule Worm_Win32_Gate_A_2147708147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gate.A"
        threat_id = "2147708147"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gate"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SAFEMODE  :   This WORM is designed only to test" ascii //weight: 1
        $x_1_2 = "with respect SafetyGate.ru" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

