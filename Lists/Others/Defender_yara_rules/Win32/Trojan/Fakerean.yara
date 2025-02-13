rule Trojan_Win32_Fakerean_PA_2147743177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fakerean.PA!MTB"
        threat_id = "2147743177"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakerean"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 cb 8d 3d ?? ?? ?? ?? 8b 00 8d 1d ?? ?? ?? ?? f7 df 81 f2 ?? ?? ?? ?? f7 d6 35 ?? ?? ?? ?? 50 f7 d2 87 f2 e9}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 45 f8 f7 da 8d 35 ?? ?? ?? ?? 33 f8 bf ?? ?? ?? ?? c1 c9 ?? 8f 00 8d 15 ?? ?? ?? ?? 81 e1 ?? ?? ?? ?? 83 c0 04 81 e1 ?? ?? ?? ?? f7 d3 33 f2 33 cf 89 f1 e9}  //weight: 2, accuracy: Low
        $x_2_3 = {89 45 f8 f7 d6 81 d7 ?? ?? ?? ?? 8b d3 ff 4d f4 0f 85 ?? ?? ?? ?? e9}  //weight: 2, accuracy: Low
        $x_1_4 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

