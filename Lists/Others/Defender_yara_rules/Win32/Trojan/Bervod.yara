rule Trojan_Win32_Bervod_A_2147630067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bervod.A"
        threat_id = "2147630067"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bervod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 02 04 00 00 50 ff 15 ?? ?? ?? ?? 8b 46 64 83 f8 02 7d 4f b9 08 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {00 00 61 00 64 00 4d 00 61 00 6e 00 49 00 65 00 57 00 6e 00 64 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bervod_C_2147630166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bervod.C"
        threat_id = "2147630166"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bervod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 41 54 4c 63 6f 6d 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_2 = "IbhoRay2009" ascii //weight: 1
        $x_1_3 = {25 73 5c 73 79 73 74 65 6d 5c 6d 73 74 73 63 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = "count=%s&data=%s&copy=%s&info=%s" ascii //weight: 1
        $x_1_5 = "User-Agent: (CustomSpy)" wide //weight: 1
        $x_3_6 = {6a 65 51 ff 15 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 52 50 ?? ?? ?? ?? ?? ?? ?? ?? ?? ff d2 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 10 8b 52 44 83 c4 0c 6a 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

