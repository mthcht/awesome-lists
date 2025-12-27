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

rule Trojan_Win32_MyDoom_AMD_2147956643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MyDoom.AMD!MTB"
        threat_id = "2147956643"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MyDoom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0f b7 c0 6a 1a 99 59 f7 f9 80 c2 61 88 54 3d e4 47 3b fe}  //weight: 3, accuracy: High
        $x_2_2 = {56 8b 35 54 10 50 00 57 8d 45 bc 68 f0 30 50 00 50 ff d6 8d 45 bc 50 ff 15 ?? ?? ?? ?? 8b f8 85 ff}  //weight: 2, accuracy: Low
        $x_1_3 = {8d 45 bc 68 d4 30 50 00 50 ff d6 8d 45 bc 50 57 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

