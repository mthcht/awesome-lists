rule Trojan_Win32_Duppatch_A_2147623652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Duppatch.A"
        threat_id = "2147623652"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Duppatch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "DuplicateHandle" ascii //weight: 1
        $x_1_2 = "NtQuerySystemInformation" ascii //weight: 1
        $x_1_3 = {74 aa 8b 3d ?? ?? 40 00 8b 0f 83 c7 04 8b d3 51 52 8b 07 3b 05 ?? ?? 40 00 0f 85 ce 00 00 00 e8 ?? ?? 00 00 8b d0 33 c0 66 8b 47 06 6a 02}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 7f 04 57 68 ?? ?? 40 00 e8 ?? ?? 00 00 83 f8 01 74 1d bf ?? ?? 40 00 b8 02 00 00 00 8b 7f 04 57 68 ?? ?? 40 00 e8 ?? ?? 00 00 83 f8 01 75 36}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

