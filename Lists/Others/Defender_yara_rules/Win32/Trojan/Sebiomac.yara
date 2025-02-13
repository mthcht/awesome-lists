rule Trojan_Win32_Sebiomac_B_2147621217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sebiomac.gen!B"
        threat_id = "2147621217"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sebiomac"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 e8 31 c6 45 e9 c0 c6 45 ea c3 c7 45 e4 00 00 00 00 89 04 24}  //weight: 1, accuracy: High
        $x_1_2 = {31 db 89 9d ?? ?? ?? ?? c6 85 ?? ?? ?? ?? c0 c6 85 ?? ?? ?? ?? c3 07 00 c6 85 ?? ?? ?? ?? 31}  //weight: 1, accuracy: Low
        $x_2_3 = {c7 04 30 5c 6c 73 61 ba 73 73 2e 65 31 c9 89 54 30 04 66 c7 44 30 08 78 65 c6 44 30 0a 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

