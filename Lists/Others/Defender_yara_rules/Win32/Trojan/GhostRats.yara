rule Trojan_Win32_GhostRats_HGP_2147932796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GhostRats.HGP!MTB"
        threat_id = "2147932796"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GhostRats"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ce 5a ae d2 34 b7 ff 94 35 3f 06 5c c0 df a1 e7 36 0c 3c 00 37 0c 16 30 2d fc 6f d2 cb 5b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

