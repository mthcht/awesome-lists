rule Trojan_Win64_NimPlant_B_2147845841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/NimPlant.B!MTB"
        threat_id = "2147845841"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "NimPlant"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {44 0f b6 0a 48 83 c2 01 41 31 c1 c1 e8 08 45 0f b6 c9 43 33 04 88 48 39 ca 75 e5 5b 5e}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

