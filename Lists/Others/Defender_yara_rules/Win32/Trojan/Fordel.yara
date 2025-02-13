rule Trojan_Win32_Fordel_A_2147644018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fordel.A"
        threat_id = "2147644018"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fordel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {40 64 65 6c 20 2f 66 20 2f 73 20 2f 71 20 65 3a 5c 2a 2e 2a 0d 0a 40 64 65 6c 20 2f 66 20 2f 73 20 2f 71 20 64 3a 5c 2a 2e 2a}  //weight: 1, accuracy: High
        $x_1_2 = "@del /f /s /q z:\\*.*" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

