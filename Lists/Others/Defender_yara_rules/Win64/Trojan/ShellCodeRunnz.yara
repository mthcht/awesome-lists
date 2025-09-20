rule Trojan_Win64_ShellCodeRunnz_ZA_2147952638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeRunnz.ZA!MTB"
        threat_id = "2147952638"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeRunnz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {62 47 68 87 03 29 3b 87 03 29 3b 87 03 29 3b 54 71 2a 3a 82 03 29 3b 54 71 2c 3a 11 03 29 3b 54 71 2d 3a 8d 03 29 3b 26 74 2d 3a 89 03 29 3b 26 74 2a 3a 8e 03 29 3b 26 74 2c 3a b7 03 29 3b 54 71 28 3a 84 03 29 3b 87}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

