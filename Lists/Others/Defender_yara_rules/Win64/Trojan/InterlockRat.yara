rule Trojan_Win64_InterlockRat_CD_2147951937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/InterlockRat.CD!MTB"
        threat_id = "2147951937"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "InterlockRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 39 d8 5b 75 ?? 48 c7 c0 01 00 00 00 c3 48 83 f8 00 0f 84 ?? ?? 00 00 ff e0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

