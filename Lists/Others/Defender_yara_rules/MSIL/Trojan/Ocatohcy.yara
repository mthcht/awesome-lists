rule Trojan_MSIL_Ocatohcy_DA_2147795881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ocatohcy.DA!MTB"
        threat_id = "2147795881"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ocatohcy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {07 09 9a 6f ?? ?? ?? 0a 13 04 11 04 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 31 05 11 04 0a 09 0c 09 17 58 0d 09 07 8e 69 32 d8}  //weight: 20, accuracy: Low
        $x_1_2 = "MSecondNumberList" ascii //weight: 1
        $x_1_3 = "Trustiry Soft" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

