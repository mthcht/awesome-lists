rule Trojan_Win64_FarFli_GX_2147949274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FarFli.GX!MTB"
        threat_id = "2147949274"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FarFli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 ff c0 48 f7 f3 0f b6 04 32 44 33 d8 41 8b cb 41 8b c3 c1 e8 0d 69 c9 ?? ?? ?? ?? 44 8b d9 44 33 d8 41 8b c3 ?? ?? ?? ?? ?? c1 e8 10 43 32 44 20 ff 41 32 c3 43 88 44 20 ff 4d 3b c5 72 bc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

