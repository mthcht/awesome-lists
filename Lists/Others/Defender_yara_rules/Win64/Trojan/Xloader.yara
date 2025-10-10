rule Trojan_Win64_Xloader_Z_2147954745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Xloader.Z!MTB"
        threat_id = "2147954745"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Xloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 f7 e8 48 8b ea 48 c1 fd 12 4c 8b c5 49 c1 e8 3f 49 03 e8 48 03 ef 41 3b f6 44 0f 42 f6 33 ff 45 85 f6 7e 29 bb 01 00 00 00 0f 1f 00 85 db 7e 0a 8b c3 f3 90 48 83 e8 01 75 f8 e8 4d ec ff ff 48 3b c5 7f 09 ff c7 d1 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

