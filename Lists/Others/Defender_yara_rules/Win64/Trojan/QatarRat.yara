rule Trojan_Win64_QatarRat_AQA_2147959261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/QatarRat.AQA!MTB"
        threat_id = "2147959261"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "QatarRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8d 0d a8 57 01 00 48 8b f8 48 8b f1 b9 3d 00 00 00 f3 a4 48 8d 84 24 ?? ?? ?? ?? 48 8b f8 33 c0 b9 c3 01 00 00 f3 aa}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

