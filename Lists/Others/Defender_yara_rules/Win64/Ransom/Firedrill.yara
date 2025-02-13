rule Ransom_Win64_Firedrill_ALJ_2147919556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Firedrill.ALJ!MTB"
        threat_id = "2147919556"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Firedrill"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KkFsbCB5b3VyI" ascii //weight: 1
        $x_1_2 = "fireDrillRansomware" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

