rule DDoS_Win32_Darktima_A_2147687941_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Win32/Darktima.A"
        threat_id = "2147687941"
        type = "DDoS"
        platform = "Win32: Windows 32-bit platform"
        family = "Darktima"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "My name is \"G-Bot\" or \"GBot\"" ascii //weight: 1
        $x_1_2 = "LnNpbXBsZWh0dHBmbG9vZA==" ascii //weight: 1
        $x_1_3 = "LnBvc3RodHRwZmxvb2Q=" ascii //weight: 1
        $x_1_4 = "Z2V0Y21kLnBocD9pZD0=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

