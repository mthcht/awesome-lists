rule Virus_Win32_Naras_A_2147582919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Naras.gen!A"
        threat_id = "2147582919"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Naras"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $n_10_1 = "PE_thunk_infect" ascii //weight: -10
        $x_3_2 = {e8 00 00 00 00 5b 81 eb ?? ?? ?? ?? 56}  //weight: 3, accuracy: Low
        $x_3_3 = {c7 07 6d 73 69 6e c7 47 04 66 6d 67 72 c7 47 08 2e 65 78 65 c7 47 0c 00 00 00 00 b9 c9 bc a6 6b 8b d6}  //weight: 3, accuracy: High
        $x_1_4 = {64 a1 30 00 00 00 8b 40 0c 8b 70 1c ad 8b 40 08 5e 8b f0}  //weight: 1, accuracy: High
        $x_1_5 = {41 ad 03 c5 33 db 0f be 10 3a d6 74 08 c1 cb 07 03 da 40 eb f1 3b df 75 e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

