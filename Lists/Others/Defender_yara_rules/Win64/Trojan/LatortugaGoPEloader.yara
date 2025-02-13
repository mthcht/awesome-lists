rule Trojan_Win64_LatortugaGoPEloader_LK_2147899304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LatortugaGoPEloader.LK!MTB"
        threat_id = "2147899304"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LatortugaGoPEloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "github.com/latortuga71/GoPeLoader/pkg/peloader" ascii //weight: 1
        $x_1_2 = "Go build ID:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

