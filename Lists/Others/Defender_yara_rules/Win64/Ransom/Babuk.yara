rule Ransom_Win64_Babuk_SR_2147850295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Babuk.SR!MTB"
        threat_id = "2147850295"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Babuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 33 c9 48 89 46 ?? 44 8b c7 8b d7 33 c9 ff 15 ?? ?? ?? ?? 45 33 c9 44 8b c7 33 d2 48 89 06 33 c9 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

