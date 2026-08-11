rule Trojan_MSIL_ASPNetInject_AB_2147975982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ASPNetInject.AB!MTB"
        threat_id = "2147975982"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ASPNetInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {0a 16 0b 2b 15 00 06 07 03 07 91 04 07 04 8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 03 8e 69 fe 04 0d 09 2d e1}  //weight: 6, accuracy: High
        $x_6_2 = {0a 16 0b 2b 13 06 07 03 07 91 04 07 04 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 03 8e 69 32 e7}  //weight: 6, accuracy: High
        $x_3_3 = "WriteProcessMemory" ascii //weight: 3
        $x_3_4 = "VirtualAllocEx" ascii //weight: 3
        $x_2_5 = "svchost.exe" wide //weight: 2
        $x_2_6 = "notepad.exe" wide //weight: 2
        $x_1_7 = {41 70 70 5f 57 65 62 5f 32 30 32 36 [0-15] 2e 61 73 70 78 2e [0-10] 2e [0-10] 2e 64 6c 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_6_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_6_*) and 2 of ($x_2_*))) or
            ((2 of ($x_6_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

