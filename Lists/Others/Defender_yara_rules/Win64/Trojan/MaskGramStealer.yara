rule Trojan_Win64_MaskGramStealer_AMK_2147960926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MaskGramStealer.AMK!MTB"
        threat_id = "2147960926"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MaskGramStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c1 83 e1 07 8a 4c 0c 08 41 32 0c 01 88 0c 02 48 ff c0 41 39 c0 7f ?? 4d 63 c0 42 c6 04 02 00 48 83 c4 10 5b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

