rule Trojan_Win64_GhostRat_LML_2147932821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GhostRat.LML!MTB"
        threat_id = "2147932821"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GhostRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d 54 11 01 80 30 a7 48 83 c0 01 48 39 d0 75 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

