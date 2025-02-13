rule Backdoor_MSIL_Cobeacon_PA_2147793713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Cobeacon.PA!MTB"
        threat_id = "2147793713"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cobeacon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "payload" ascii //weight: 1
        $x_1_2 = "Hollower" ascii //weight: 1
        $x_1_3 = {26 16 0d 2b ?? 07 09 04 09 91 28 ?? ?? ?? ?? 09 17 58 0d 09 04 8e 69 32}  //weight: 1, accuracy: Low
        $x_1_4 = {26 11 10 16 28 ?? ?? ?? ?? 13 11 11 11 6a 11 0e 6f ?? ?? ?? ?? 11 0e 6f ?? ?? ?? ?? 59 30 16 11 11 8d ?? ?? ?? ?? 13 05 11 0e 11 05 16 11 11 6f ?? ?? ?? ?? 26 de}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

