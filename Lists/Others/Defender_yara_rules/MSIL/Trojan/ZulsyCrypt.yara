rule Trojan_MSIL_ZulsyCrypt_A_2147839111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZulsyCrypt.A!MTB"
        threat_id = "2147839111"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZulsyCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 09 20 ff 00 00 00 9c 09 17 58 0d 09 08 8e 69}  //weight: 2, accuracy: High
        $x_2_2 = {25 17 58 13 0a 91 08 61 d2 9c 09 17 5f}  //weight: 2, accuracy: High
        $x_1_3 = "GetDelegateForFunctionPointer" ascii //weight: 1
        $x_1_4 = "get_EntryPoint" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

