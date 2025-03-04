rule Backdoor_MSIL_NanoCore_DH_2147783090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/NanoCore.DH!MTB"
        threat_id = "2147783090"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 0b 07 28 ?? ?? ?? ?? 04 6f ?? ?? ?? ?? ?? ?? ?? ?? ?? 0c 73 ?? ?? ?? ?? 0d 09 08 6f ?? ?? ?? ?? 00 09 18 6f ?? ?? ?? ?? ?? 09 6f ?? ?? ?? ?? 13 04 11 04 05 16 05 8e 69 6f ?? ?? ?? ?? 13 05 09 6f ?? ?? ?? ?? 00 11 05 0a 2b 00 06 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "Replace" ascii //weight: 1
        $x_1_3 = "Split" ascii //weight: 1
        $x_1_4 = "ToString" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

