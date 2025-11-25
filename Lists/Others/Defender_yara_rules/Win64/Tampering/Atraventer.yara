rule Tampering_Win64_Atraventer_A_2147958169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Tampering:Win64/Atraventer.A"
        threat_id = "2147958169"
        type = "Tampering"
        platform = "Win64: Windows 64-bit platform"
        family = "Atraventer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 56 53 48 81 ec 90 02 00 00 e8 ?? ?? ?? ?? 48 0f bf 15 ?? ?? ?? ?? 41 b9 97 96 ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

