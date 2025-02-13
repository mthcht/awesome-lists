rule Trojan_Win64_ThunderStl_C_2147919385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ThunderStl.C"
        threat_id = "2147919385"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ThunderStl"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Standalone values not allowed. Was given: {}" ascii //weight: 1
        $x_1_2 = "Config file contents:" ascii //weight: 1
        $x_1_3 = "DQAADQAADQAADQAA" ascii //weight: 1
        $x_1_4 = "C:\\ProgramData\\chocolatey\\lib\\Connhost\\tools\\sb.conf" ascii //weight: 1
        $x_1_5 = "GetComputerNameA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

