rule Trojan_Win64_AveMaria_CRHX_2147847981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AveMaria.CRHX!MTB"
        threat_id = "2147847981"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b c7 83 e0 0f 0f b6 04 10 f6 d0 30 04 39 48 ff c7 48 3b 3e 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

