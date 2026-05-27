rule Trojan_Win64_Inoci_PAHL_2147970240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Inoci.PAHL!MTB"
        threat_id = "2147970240"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Inoci"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {41 8b d5 d3 ea 0f b6 d2 41 8b de d3 eb 0f b6 db 32 d3 42 0f b6 04 3e 8b f8 32 c2 42 88 04 3e 44 03 f7 41 ff c7 eb}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

