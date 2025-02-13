rule Trojan_Win64_Sodinokibi_2147777660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sodinokibi!MTB"
        threat_id = "2147777660"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sodinokibi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec e9 07 00 55 8b ec 8b 75 08 8b 7d 0c 8b 55 10 b1 07 ac e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

