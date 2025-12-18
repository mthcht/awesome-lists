rule Trojan_Win64_Encoder_SK_2147959729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Encoder.SK!MTB"
        threat_id = "2147959729"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Encoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".CNMSBNMSL" ascii //weight: 1
        $x_1_2 = "\\READ_THIS_FIRST.txt" ascii //weight: 1
        $x_1_3 = ": 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" ascii //weight: 1
        $x_1_4 = ": recover@protonmail.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

