rule Trojan_Win32_LgoogLoader_MA_2147828811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LgoogLoader.MA!MTB"
        threat_id = "2147828811"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LgoogLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 c8 8b 45 c4 03 45 fc 89 45 cc 8b 45 f8 03 45 f4 39 45 d0 73 ?? 8b 45 c8 03 45 d0 8b 4d cc 03 4d d0 8a 11 88 10 8b 45 d0 83 c0 01 89 45 d0 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LgoogLoader_EH_2147834814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LgoogLoader.EH!MTB"
        threat_id = "2147834814"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LgoogLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ok.txt" wide //weight: 1
        $x_1_2 = "0.png" wide //weight: 1
        $x_1_3 = "kav wipel nesexi jilov-ficaque./quowa visova quip xelo" wide //weight: 1
        $x_1_4 = "GetFileAttributesW" ascii //weight: 1
        $x_1_5 = "CreateFileW" ascii //weight: 1
        $x_1_6 = "nadique.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LgoogLoader_GCW_2147838561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LgoogLoader.GCW!MTB"
        threat_id = "2147838561"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LgoogLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 02 33 c1 8b 0d ?? ?? ?? ?? 03 4d c4 88 01 eb 32 00 0f b6 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 55}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

