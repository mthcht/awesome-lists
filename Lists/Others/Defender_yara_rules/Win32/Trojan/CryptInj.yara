rule Trojan_Win32_CryptInj_BA_2147742433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInj.BA!MTB"
        threat_id = "2147742433"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInj"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f7 c1 e6 04 03 f2 33 d2 3d df 03 00 00 0f 44 ca 8b d7 c1 ea 05 03 95 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 03 cf 33 d1 33 d6 2b da 8b fb c1 e7 04 3d 93 04 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c7 08 4e 75 09 00 8b d3 8b cf 55 8b [0-208] 20 00 00 00 8b 0d [0-7] c1 e6 04 [0-32] c1 ea 05 03 95 ?? ?? ?? ?? 89 0d [0-32] c1 e7 04 3d ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

