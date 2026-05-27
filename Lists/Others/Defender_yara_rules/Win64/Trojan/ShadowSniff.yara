rule Trojan_Win64_ShadowSniff_GDK_2147970225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShadowSniff.GDK!MTB"
        threat_id = "2147970225"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShadowSniff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {80 f1 e7 0f b6 c9 c1 e1 08 83 f0 1f 09 c8 80 f2 31 88}  //weight: 10, accuracy: High
        $x_1_2 = "ShadowSniff.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

