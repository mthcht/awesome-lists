rule Trojan_Win64_Salat_MK_2147975191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Salat.MK!MTB"
        threat_id = "2147975191"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Salat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {c7 44 24 30 40 00 00 00 48 8b cf 83 e8 09 c7 44 24 28 09 00 00 00 99 c7 44 24 20 de 00 00 00 2b c2 d1 f8 44 8b c8 8d 83 22 ff ff ff}  //weight: 20, accuracy: High
        $x_10_2 = "OnlyBarLoaderClass" wide //weight: 10
        $x_5_3 = "dllinjectOverlay.exe.dll" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

