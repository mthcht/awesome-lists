rule Trojan_Win64_Casbaneiro_ARAX_2147959398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Casbaneiro.ARAX!MTB"
        threat_id = "2147959398"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Casbaneiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 01 8b d0 33 d6 42 8d 34 00 81 e6 ff 00 00 80 7d 0a ff ce 81 ce 00 ff ff ff ff c6 88 11 48 ff c1 49 3b c9 72 d9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

