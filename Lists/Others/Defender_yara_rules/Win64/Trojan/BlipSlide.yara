rule Trojan_Win64_BlipSlide_A_2147935267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlipSlide.A!dha"
        threat_id = "2147935267"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlipSlide"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = ".?AVIceDrive@@" ascii //weight: 10
        $x_10_2 = ".?AV?$WinHttpWrapper@VIceDrive@@@@" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlipSlide_B_2147935268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlipSlide.B!dha"
        threat_id = "2147935268"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlipSlide"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {48 83 7c 24 48 ?? 0f 83 50 00 00 00 48 8b 4c 24 40 8a 01 88 44 24 2e 48 83 c1 01 48 8b 54 24 48 e8 ?? ?? ?? ?? 8a 54 24 2e 8a 08 e8 ?? ?? ?? ?? 48 8b 4c 24 30 88 44 24 2f 48 8b 54 24 48 e8 ?? ?? ?? ?? 8a 4c 24 2f 88 08 48 8b 44 24 48 48 83 c0 01 48 89 44 24 48}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

