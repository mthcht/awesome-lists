rule Trojan_Win64_LovGate_CCJX_2147941323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LovGate.CCJX!MTB"
        threat_id = "2147941323"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LovGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b7 4c 70 fe 89 ca c1 ea 08 31 ca 88 54 37 ff 48 83 fe 43 74 ?? 0f b7 0c 70 89 ca c1 ea 08 31 ca 88 14 37 48 83 c6 02 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

