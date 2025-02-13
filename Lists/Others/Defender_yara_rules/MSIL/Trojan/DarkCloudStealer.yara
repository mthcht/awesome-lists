rule Trojan_MSIL_DarkCloudStealer_B_2147837526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloudStealer.B!MTB"
        threat_id = "2147837526"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloudStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 01 25 16 1f ?? 9d 6f ?? 00 00 0a 06 00 00 00 0a 17 8d}  //weight: 2, accuracy: Low
        $x_2_2 = {08 09 07 09 9a 1f ?? 28 ?? 00 00 0a 9c 09 17 d6}  //weight: 2, accuracy: Low
        $x_2_3 = {00 00 0a 1b 9a 0a 06 14 72 ?? ?? ?? 70 17 8d ?? 00 00 01 25 16 72 ?? ?? ?? 70 a2 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 07 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloudStealer_A_2147839032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloudStealer.A!MTB"
        threat_id = "2147839032"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloudStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 01 25 16 1f ?? 9d 6f ?? ?? 00 0a 0b 05 00 00 0a 17 8d}  //weight: 2, accuracy: Low
        $x_2_2 = {00 00 01 25 16 1f ?? 9d 6f ?? ?? 00 0a 0d 05 00 00 04 17 8d}  //weight: 2, accuracy: Low
        $x_2_3 = {08 06 07 06 9a 1f 10 28 ?? ?? 00 0a 9c 06 17 d6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloudStealer_C_2147840695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloudStealer.C!MTB"
        threat_id = "2147840695"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloudStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 09 06 8e 69 5d 02 06 09 28}  //weight: 2, accuracy: High
        $x_2_2 = {09 15 58 0d}  //weight: 2, accuracy: High
        $x_2_3 = {03 04 03 8e 69 5d 91 06 04 1f ?? 5d 91 61 28 ?? 00 00 0a 03 04 17 58 03 8e 69 5d 91 28 ?? 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

