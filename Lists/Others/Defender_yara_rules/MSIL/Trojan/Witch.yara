rule Trojan_MSIL_Witch_W_2147782479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Witch.W!MTB"
        threat_id = "2147782479"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Witch"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {03 58 0c 08 69 19 5f 3a 09 00 00 00 08 4a 13 04 dd 36 00 00 00 12 01 e0 0d 09 08 47 52 09 17 d3 58 08 17 d3 58 47 52 09 18 d3 58 08 18 d3 58 47 52 09 19 d3 58 08 19 d3 58 47 52 07 0a}  //weight: 10, accuracy: High
        $x_3_2 = "Windows.DROP.resources" ascii //weight: 3
        $x_3_3 = "{11111-22222-20001-00002}" ascii //weight: 3
        $x_3_4 = "CreateDecryptor" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Witch_MA_2147809052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Witch.MA!MTB"
        threat_id = "2147809052"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Witch"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$$method0x600001c-1" ascii //weight: 1
        $x_1_2 = "$$method0x60001fd-1" ascii //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
        $x_1_4 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_1_5 = ".vmp0" ascii //weight: 1
        $x_1_6 = "MemoryStream" ascii //weight: 1
        $x_1_7 = "Debug" ascii //weight: 1
        $x_1_8 = "Corrupted" ascii //weight: 1
        $x_1_9 = "get_MachineName" ascii //weight: 1
        $x_1_10 = "DownloadData" ascii //weight: 1
        $x_1_11 = "FromBase64" ascii //weight: 1
        $x_1_12 = "CreateDecryptor" ascii //weight: 1
        $x_1_13 = "IsLogging" ascii //weight: 1
        $x_1_14 = "set_Key" ascii //weight: 1
        $x_1_15 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Witch_SG_2147912372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Witch.SG!MTB"
        threat_id = "2147912372"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Witch"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 30 6f 0b 00 00 0a 28 03 00 00 06 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

