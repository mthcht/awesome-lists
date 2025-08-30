rule Trojan_Win32_MetaSpliot_TRK_2147950831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MetaSpliot.TRK!MTB"
        threat_id = "2147950831"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MetaSpliot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 b8 3d 4e e9 c2 b1 b3 50 fe 48 ba a6 0f 01 c7 97 b1 1b e5 48 89 45 10 48 89 55 18 48 b8 9b 5d 99 e6 f8 70 b3 f1 48 ba ca 9c 72 a5 6b 62 21 79 48 89 45 20 48 89 55 28 48 b8 b7 32 55 bf 2d bf 2a bd 48 ba 66 a9 83 3f 87 4e c4 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

