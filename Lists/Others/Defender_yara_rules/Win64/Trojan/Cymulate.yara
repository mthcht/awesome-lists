rule Trojan_Win64_Cymulate_ACM_2147895964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cymulate.ACM!MTB"
        threat_id = "2147895964"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cymulate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 89 74 24 44 33 d2 41 b8 00 10 00 00 48 8d 4c 24 60 e8 ?? ?? ?? ?? 48 8d 54 24 44 48 8b cd ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

