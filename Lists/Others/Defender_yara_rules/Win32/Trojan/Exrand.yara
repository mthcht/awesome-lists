rule Trojan_Win32_Exrand_2147615679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Exrand"
        threat_id = "2147615679"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Exrand"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {00 63 6f 66 66 65 65 62 6f 6f 6b 2e 63 6f 2e 6b 72 00 00}  //weight: 3, accuracy: High
        $x_2_2 = "EVT_FD0A4F40-0340-40ab" ascii //weight: 2
        $x_2_3 = "D1BAC1AB-9220-435f-89FF-E8314F87437B" ascii //weight: 2
        $x_1_4 = {5c 73 79 73 74 65 6d 33 32 5c 00 00 5c 73 79 73 74 65 6d 5c}  //weight: 1, accuracy: High
        $x_1_5 = "%s\\hosts.sam" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

