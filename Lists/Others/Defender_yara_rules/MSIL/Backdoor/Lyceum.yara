rule Backdoor_MSIL_Lyceum_JFV_2147828128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Lyceum.JFV!MTB"
        threat_id = "2147828128"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lyceum"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 08 11 04 8f 4e 00 00 01 72 de 09 00 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 11 04 17 58 13 04 11 04 08 8e 69 32 da}  //weight: 1, accuracy: Low
        $x_1_2 = "cyberclub.one" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

