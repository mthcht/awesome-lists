rule Trojan_Win64_Boxter_AP_2147982841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Boxter.AP!MTB"
        threat_id = "2147982841"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Boxter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_9_1 = "JAB1AD0AJwBoAHQAdABwAHMAOgAvAC8AdwB3AHcALgBkAHIAbwBwAGIAbwB4AC4AYwBvAG0ALwBz" ascii //weight: 9
        $x_1_2 = "AGMAbAAvAGYAaQAvAHcAdAA3ADYAZwBrAHoAMABlAHgAOABrADkAYwBxADUANgB4AGYAY" ascii //weight: 1
        $x_8_3 = "A6AFQARQBNAFAAKwAnAFwAQwBoAHIAbwBtAGUAVwBlAGIAUwBvAGMAawBlA" ascii //weight: 8
        $x_2_4 = "ACQAcAApADsAUwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgACQAcAAgAC0AVwBpAG4AZABvAHcAUwB0AHkAbAB" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

