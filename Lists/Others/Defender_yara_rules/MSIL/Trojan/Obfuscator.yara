rule Trojan_MSIL_Obfuscator_PF_2147747862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Obfuscator.PF!MTB"
        threat_id = "2147747862"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 6f 00 00 04 7e 6d 00 00 04 28 ?? ?? 00 06 7e 6f 00 00 04 16 6a 28 ?? ?? 00 06 06 16 28 ?? ?? 00 06 25 26 13 10 20 e8 03 00 00 13 11 11 11 8d 0b 00 00 01 13 13 11 10 11 13 16 11 11 28 ?? ?? 00 06 25 26 13 12 11 12 16 31 19}  //weight: 1, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "GetDrives" ascii //weight: 1
        $x_1_4 = "GetPhysicalAddress" ascii //weight: 1
        $x_1_5 = "GetAllNetworkInterfaces" ascii //weight: 1
        $x_1_6 = "get_xls" ascii //weight: 1
        $x_1_7 = "get_doc" ascii //weight: 1
        $x_1_8 = "get_odc" ascii //weight: 1
        $x_1_9 = "SerialUSB" ascii //weight: 1
        $x_1_10 = "FileDocTemp" ascii //weight: 1
        $x_1_11 = "USBSerialNumber" ascii //weight: 1
        $x_1_12 = "PingReply" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Obfuscator_WFL_2147758046_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Obfuscator.WFL!MTB"
        threat_id = "2147758046"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "srnyjejnetdnrtsgxzgdtjzjdg" ascii //weight: 1
        $x_1_2 = "$5D627E47-66E3-4635-B9C2-49AC0B5EC0D9" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

