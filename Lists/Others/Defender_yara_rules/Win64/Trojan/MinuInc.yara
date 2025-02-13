rule Trojan_Win64_MinuInc_V_2147754997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MinuInc.V!MTB"
        threat_id = "2147754997"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MinuInc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MinuetsOs Inc" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

