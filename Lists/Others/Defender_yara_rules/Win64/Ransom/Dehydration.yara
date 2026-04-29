rule Ransom_Win64_Dehydration_AB_2147967966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Dehydration.AB!MTB"
        threat_id = "2147967966"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Dehydration"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Your system has been transformed into a critical system. Dehydration ransomware. " ascii //weight: 2
        $x_2_2 = "config vss start= disabled" ascii //weight: 2
        $x_2_3 = "System dehydration in progress" ascii //weight: 2
        $x_2_4 = "CRITICAL_DEHYDRATION_DETECTED" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

