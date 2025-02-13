rule Trojan_Win64_Kegrelodr_B_2147907954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Kegrelodr.B!MTB"
        threat_id = "2147907954"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Kegrelodr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 d3 20 cb 30 ca 41 89 d8 41 30 d0 84 d2 b9 ?? ?? ?? ?? 41 0f 45 cf 84 db ba ?? ?? ?? ?? 0f 44 ca 48 89 ?? ?? 45 84 c0 41 0f 45 cf}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

