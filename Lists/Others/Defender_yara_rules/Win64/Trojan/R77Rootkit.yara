rule Trojan_Win64_R77Rootkit_CCIL_2147912222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/R77Rootkit.CCIL!MTB"
        threat_id = "2147912222"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "R77Rootkit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 44 03 d0 c1 ca ?? 41 80 39 61 8d 41 e0 0f 4c c1 03 d0 49 ff c1 66 45 85 d2 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

