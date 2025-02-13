rule Trojan_Win64_Fsysna_NFC_2147899903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Fsysna.NFC!MTB"
        threat_id = "2147899903"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Fsysna"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {75 e2 48 8b 84 24 ?? ?? ?? ?? 89 44 24 28 48 8d 84 24 ?? ?? ?? ?? 48 89 44 24 20 41 b9 ?? ?? ?? ?? 45 33 c0 48 8d 15 a9 d0 02 00}  //weight: 5, accuracy: Low
        $x_1_2 = "CmNtZC5leGUgL2Mg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

