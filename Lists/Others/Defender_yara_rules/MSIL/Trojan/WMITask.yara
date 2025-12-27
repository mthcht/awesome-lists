rule Trojan_MSIL_WMITask_HB_2147948570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WMITask.HB!MTB"
        threat_id = "2147948570"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WMITask"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 11 72 01 00 00 70 0a 02 6f 14 00 00 0a 72 ?? 00 00 70 6f 15 00 00 0a 06 72 ?? 00 00 70 28 16 00 00 0a 0b 02 6f 14 00 00 0a 72 ?? 00 00 70 6f 15 00 00 0a 0c 07 08 28 06 00 00 06 [0-36] 26 de 00 16 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {00 00 70 6f 15 00 00 0a 17 8d ?? ?? 00 01 25 16 1f 2c 9d 6f ?? 00 00 0a 0b 06 07 28 19 00 02 6f ?? 00 00 0a 72 01 00 00 70 6f ?? 00 00 0a 0a 02 6f ?? 00 00 0a 72 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

