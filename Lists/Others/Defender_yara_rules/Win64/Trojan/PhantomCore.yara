rule Trojan_Win64_PhantomCore_EM_2147976212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PhantomCore.EM!MTB"
        threat_id = "2147976212"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PhantomCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 0f af d0 49 89 d2 49 01 ca 4c 89 d2 45 89 d3 41 c1 ea 18 41 c1 eb 08 45 31 d3 45 89 da 47 30 1c 08}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

