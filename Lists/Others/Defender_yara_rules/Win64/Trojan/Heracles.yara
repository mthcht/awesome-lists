rule Trojan_Win64_Heracles_TMX_2147948036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Heracles.TMX!MTB"
        threat_id = "2147948036"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "$85BA0DFC-746D-4292-997C-9EFAE29CA57F" ascii //weight: 4
        $x_4_2 = "C:\\webview2\\webview2\\obj\\Release\\webview2.pdb" ascii //weight: 4
        $x_1_3 = "Palindrome" ascii //weight: 1
        $x_1_4 = "Fahrenheit" ascii //weight: 1
        $x_1_5 = "GetRandomWord" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

