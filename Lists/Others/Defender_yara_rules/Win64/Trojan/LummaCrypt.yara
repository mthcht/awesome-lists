rule Trojan_Win64_LummaCrypt_LKA_2147896773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaCrypt.LKA!MTB"
        threat_id = "2147896773"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 ca 48 c1 ea ?? 48 c1 f9 ?? 01 d1 69 c9 ?? ?? 00 00 29 c8 89 04 bb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

