rule Trojan_Win64_ShellCodeInject_ST_2147964905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeInject.ST!MTB"
        threat_id = "2147964905"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f be 04 01 48 8b 4c 24 20 48 8b 54 24 40 48 03 d1 48 8b ca 0f b6 09 33 c8 8b c1 48 8b 4c 24 20 48 8b 54 24 40 48 03 d1 48 8b ca 88 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

