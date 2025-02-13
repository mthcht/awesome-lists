rule Trojan_MSIL_VIPKeylogger_PLIRH_2147932157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VIPKeylogger.PLIRH!MTB"
        threat_id = "2147932157"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VIPKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0c 08 06 6f ?? 00 00 0a 08 07 6f ?? 00 00 0a 08 6f ?? 00 00 0a 0d 09 03 16 03 8e 69 6f ?? 00 00 0a 13 04 dd ?? 00 00 00 09}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

