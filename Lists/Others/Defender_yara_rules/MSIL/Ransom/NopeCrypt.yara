rule Ransom_MSIL_NopeCrypt_PA_2147805122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/NopeCrypt.PA!MTB"
        threat_id = "2147805122"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NopeCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XEBSRUFEX01FQC50eHQ=" wide //weight: 1
        $x_1_2 = "d2JhZG1pbiBkZWxldGUgY2F0YWxvZyAtcXVpZXQ=" wide //weight: 1
        $x_1_3 = "dnNzYWRtaW4gZGVsZXRlIHNoYWRvd3MgL2FsbCAvcXVpZXQgJiB3bWljIHNoYWRvd2NvcHkgZGVsZXRl" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

