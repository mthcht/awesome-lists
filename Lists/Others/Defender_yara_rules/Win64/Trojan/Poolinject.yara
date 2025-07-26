rule Trojan_Win64_Poolinject_PGP_2147947496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Poolinject.PGP!MTB"
        threat_id = "2147947496"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Poolinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {66 0f ef 4d f7 41 8b c8 66 48 0f 7e c8 48 89 75 07 48 89 7d 0f 66 0f ef 45 07 66 0f 7f 45 d7 66 0f 7f 4d c7 0f be d0 84 c0 74}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

