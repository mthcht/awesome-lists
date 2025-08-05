rule Trojan_Win64_ValleyRAT_PAHM_2147947493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRAT.PAHM!MTB"
        threat_id = "2147947493"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8d 4c 24 40 ?? ?? 48 8b 44 24 40 48 2b 44 24 30 0f 57 c9 f2 48 0f 2a c8 0f 57 c0 f2 48 0f 2a 44 24 38 f2 0f 5e c8 66 0f 2f f1}  //weight: 2, accuracy: Low
        $x_2_2 = {48 8b 44 24 48 48 2b 44 24 30 0f 57 c9 f2 48 0f 2a c8 0f 57 c0 f2 48 0f 2a 44 24 38 f2 0f 5e c8 f2 ?? ?? ?? ?? ?? ?? ?? f2 0f 2c c1 3d 88 13 00 00 7e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

