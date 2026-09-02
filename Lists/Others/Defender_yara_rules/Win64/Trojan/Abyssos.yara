rule Trojan_Win64_Abyssos_PAA_2147976073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Abyssos.PAA!MTB"
        threat_id = "2147976073"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Abyssos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {41 81 f2 77 e7 b1 26 41 29 c2 0d 77 e7 b1 26 81 ca 88 18 4e d9 41 01 d2 41 01 c2 41 ff c2 89 c8 31 d2 41 f7 f2 48 63 c2 42 0f b6 44 00 13 42 32 44 01 2c 42 88 04 09 8d 04 09 f7 d0}  //weight: 3, accuracy: High
        $x_1_2 = "[!] Memory alloclocate binary da[!] Failed to alEXECLOCAL_AES_HOs|%s|v2.4F|%s|%sHELLO|%s|%s|%s|%d" ascii //weight: 1
        $x_1_3 = "[!] Failed to ex[!] Failed to crR|%s|load_failedGRABCOOKIES_ERROR|%s|abyss_not_f[!] Failed to start hidden cmd.e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Abyssos_ABS_2147977360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Abyssos.ABS!MTB"
        threat_id = "2147977360"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Abyssos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 31 ce 89 c8 31 d2 f7 f6 48 63 c2 42 0f b6 44 00 ?? 89 c2 01 ca 44 20 da 00 d2 41 00 c3 41 28 d3 41 0f b6 c3 01 c8 42 88 04 11 8d 41 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

