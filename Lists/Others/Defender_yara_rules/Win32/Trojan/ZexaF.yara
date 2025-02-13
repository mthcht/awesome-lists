rule Trojan_Win32_ZexaF_NF_2147933073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ZexaF.NF!MTB"
        threat_id = "2147933073"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ZexaF"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 85 98 fa ff ff 89 06 8a 85 ?? ?? ff ff 88 46 04 8d 85 ?? ?? ff ff 50 ff b5 ?? ?? ff ff 6a 05 56 57}  //weight: 3, accuracy: Low
        $x_2_2 = {ff ff 50 8d 45 c0 66 c7 45 d0 22 00 50 8d 85 ?? ?? ff ff 50 0f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

