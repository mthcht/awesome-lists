rule Trojan_Win32_MyDoom_RF_2147891470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MyDoom.RF!MTB"
        threat_id = "2147891470"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MyDoom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 c1 29 d9 83 c1 0d b8 4f ec c4 4e f7 e9 c1 fa 03 89 c8 c1 f8 1f 29 c2 8d 04 52 8d 04 82 01 c0 29 c1 0f be 54 29 d8 eb 42}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

