rule Trojan_Win64_PostGallery_A_2147926518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PostGallery.A!dha"
        threat_id = "2147926518"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PostGallery"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {73 68 65 6c 6c 65 78 65 e9 ?? ?? ?? ?? 48 83 fe 09 0f 85 ?? ?? ?? ?? ?? ?? 73 68 65 6c 6c 65 78 65}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

