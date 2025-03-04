rule Trojan_Win64_plugx_2147844412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/plugx.psyF!MTB"
        threat_id = "2147844412"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "plugx"
        severity = "Critical"
        info = "psyF: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {85 c9 76 74 48 8b 4c 24 68 48 89 4c 24 70 48 8d 05 5b 6e 00 00 e8 76 de f9 ff 48 8b 4c 24 58 48 89 08 48 8b 54 24 70 48 89 50 08 48 8b 54 24 48}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

