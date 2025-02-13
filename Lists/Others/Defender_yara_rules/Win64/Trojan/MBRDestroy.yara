rule Trojan_Win64_MBRDestroy_RDA_2147852853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MBRDestroy.RDA!MTB"
        threat_id = "2147852853"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MBRDestroy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4c 8d 4c 24 40 48 c7 44 24 20 00 00 00 00 48 8b c8 48 8d 15 ?? ?? ?? ?? 41 b8 00 02 00 00 48 8b d8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

