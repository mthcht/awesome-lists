rule Trojan_MSIL_LaplasClipper_B_2147849328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LaplasClipper.B!MTB"
        threat_id = "2147849328"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LaplasClipper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {93 fe 09 02 00 61 d1 9d}  //weight: 2, accuracy: High
        $x_2_2 = "ClipboardManager" ascii //weight: 2
        $x_2_3 = "GetNewAddress" ascii //weight: 2
        $x_2_4 = "SetOnline" ascii //weight: 2
        $x_2_5 = "RefreshRegex" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LaplasClipper_C_2147849329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LaplasClipper.C!MTB"
        threat_id = "2147849329"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LaplasClipper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 ff a2 3f 09 0f 00 00 00 00 00 00 00 00 00 00 02 00 00 00 b8 00 00 00 28 00 00 00 59 00 00 00 de 01}  //weight: 2, accuracy: High
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

