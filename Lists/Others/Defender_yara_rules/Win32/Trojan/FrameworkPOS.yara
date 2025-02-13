rule Trojan_Win32_FrameworkPOS_PA_2147748088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FrameworkPOS.PA!MTB"
        threat_id = "2147748088"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FrameworkPOS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 fc 83 c0 01 89 45 fc 83 7d fc 46 7d 16 8b 4d 08 03 4d fc 0f be 11 83 f2 4d 8b 45 08 03 45 fc 88 10 eb db}  //weight: 1, accuracy: High
        $x_1_2 = {55 8b ec 51 0f b6 45 0c 33 d2 b9 08 00 00 00 f7 f1 88 55 0c 0f b6 55 08 0f b6 4d 0c d3 fa 88 55 ff 0f b6 45 08 0f b6 4d 0c ba 08 00 00 00 2b d1 8b ca d3 e0 88 45 fe 0f b6 45 ff 0f b6 4d fe 0b c1 8b e5 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

