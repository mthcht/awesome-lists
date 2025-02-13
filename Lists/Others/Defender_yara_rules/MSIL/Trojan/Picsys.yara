rule Trojan_MSIL_Picsys_SK_2147931779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Picsys.SK!MTB"
        threat_id = "2147931779"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Picsys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 07 59 8d 27 00 00 01 0d 02 07 09 16 09 8e 69 28 1d 00 00 0a 06 09 6f 1e 00 00 0a 08 03 8e 69 58 0b 02 03 07 28 04 00 00 06 0c 08 16 fe 04 2c cf}  //weight: 2, accuracy: High
        $x_2_2 = "stub.exe.Properties" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

