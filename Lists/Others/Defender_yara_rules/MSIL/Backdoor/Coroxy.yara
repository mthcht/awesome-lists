rule Backdoor_MSIL_Coroxy_NA_2147839768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Coroxy.NA!MTB"
        threat_id = "2147839768"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Coroxy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {20 7c 6a 00 00 28 ?? ?? 00 06 2b 3c 28 ?? ?? 00 0a 08 6f ?? ?? 00 0a 2b 24 07 8e 69 8d ?? ?? 00 01 13 04 16 13 05 2b 23 11 04 11 05 09 11 05 09 8e 69 5d 91 07 11 05 91 61 d2 9c 2b 03 0d 2b d9 11 05 17 58 13 05 2b 03 0c 2b c1 11 05 07 8e 69 32 02 2b 05}  //weight: 5, accuracy: Low
        $x_1_2 = "Egkwlniwxr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

