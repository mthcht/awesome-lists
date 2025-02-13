rule Trojan_Win64_Themida_BK_2147809804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Themida.BK!MTB"
        threat_id = "2147809804"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Themida"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {99 1c bf b4 7a 30 03 85 d1 3e 70 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

