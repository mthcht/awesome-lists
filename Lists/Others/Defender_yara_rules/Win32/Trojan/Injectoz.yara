rule Trojan_Win32_Injectoz_Z_2147952304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injectoz.Z!MTB"
        threat_id = "2147952304"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injectoz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 79 04 83 c6 04 83 ea 04 83 c0 10 83 e9 10 3b f2 7c c4 5d ba 01 00 00 00 39 93 f0 00 00 00 0f 8e b6 01 00 00 8d 43 02 8b 48 0e 0f b6 78 0f 8b 3c bd 18 75 40 00 83 c0 10 8b f1 c1 ee 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

