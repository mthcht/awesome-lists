rule Trojan_Win32_Etaclef_A_2147656118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Etaclef.gen!A"
        threat_id = "2147656118"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Etaclef"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {76 07 fe c2 80 c1 ?? 88 08 0f b6 30 2b de 47 84 d2 56}  //weight: 2, accuracy: Low
        $x_1_2 = "EXE_STARTER" ascii //weight: 1
        $x_2_3 = {83 e8 37 83 f8 21 7d 03 83 c0 5e 88 04 32 42 3b d1 7c de}  //weight: 2, accuracy: High
        $x_1_4 = "DLL_STARTER" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

