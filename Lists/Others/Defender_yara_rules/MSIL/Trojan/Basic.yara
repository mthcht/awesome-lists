rule Trojan_MSIL_Basic_SK_2147852032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Basic.SK!MTB"
        threat_id = "2147852032"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Basic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 0b 17 58 13 0b 06 11 0a 11 0b 58 91 06 07 11 0b 58 91 33 05 11 0b 09 32 e6}  //weight: 2, accuracy: High
        $x_2_2 = "piri.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Basic_KAA_2147921792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Basic.KAA!MTB"
        threat_id = "2147921792"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Basic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {28 32 01 00 06 fe 0e 01 00 28 33 01 00 06 28 34 01 00 06 28 35 01 00 06 61 28 36 01 00 06 40 10 00 00 00 28 37 01 00 06 fe 0e 01 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Basic_A_2147936819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Basic.A!MTB"
        threat_id = "2147936819"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Basic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 0a 02 06 16 1a 6f a2 00 00 0a 26 06 16 28 63 00 00 0a 0b 07 8d 46 00 00 01 0c 02 08 16 07 6f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

