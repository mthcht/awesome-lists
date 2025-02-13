rule Trojan_Win32_Kplo_A_2147642545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kplo.A"
        threat_id = "2147642545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kplo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff e0 cc cc cc cc 0e 00 cc cc cc cc 68 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 68 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {00 5c 6c 70 6b 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {4c 70 6b 49 6e 69 74 69 61 6c 69 7a 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kplo_B_2147642703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kplo.B"
        threat_id = "2147642703"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kplo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff e0 cc cc cc cc 0e 00 cc cc cc cc 68 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {00 5c 6c 70 6b 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {4c 70 6b 49 6e 69 74 69 61 6c 69 7a 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "MemCode_Lpk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

