rule Backdoor_Win32_Morat_A_2147680298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Morat.A"
        threat_id = "2147680298"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Morat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/u.php?ver=%s&mid=%s" wide //weight: 1
        $x_1_2 = "wide_search_close_message" wide //weight: 1
        $x_1_3 = "ping -n 10 127.0.0.1 > NUL" wide //weight: 1
        $x_1_4 = {68 e8 03 00 00 e8 ?? ?? ?? ?? 33 c9 b2 01 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 45 ?? 8b 45 ?? c6 80 40 01 00 00 01 8d 45 ?? 50 66 c7 45 ?? 32 00 c6 45 ?? 09 a1 ?? ?? ?? ?? 89 45 ?? c6 45 ?? 11 8d 55 ?? b9 01 00 00 00 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 ?? 8b 4d ?? 8b 45 ?? e8 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 45 ?? ba 03 00 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Morat_B_2147680299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Morat.B"
        threat_id = "2147680299"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Morat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 8d 45 ?? 50 66 c7 45 ?? 36 00 c6 45 ?? 09 a1 ?? ?? ?? ?? 89 45 ?? c6 45 ?? 11 8b 45 ?? 89 45 ?? c6 45 ?? 11 89 5d ?? c6 45 ?? 00 8d 45 ?? 50}  //weight: 1, accuracy: Low
        $x_1_2 = "s%=dim&s%=rev?php.j/" wide //weight: 1
        $x_1_3 = "d%=ser&s%=yek&s%=dim&s%=rev?php.r/" wide //weight: 1
        $x_1_4 = "s%=bus&s%=dim&s%=rev?php.u/" wide //weight: 1
        $x_1_5 = "EgAsSeM_eSoLc_HcRaEs_eDiW" wide //weight: 1
        $x_1_6 = "tad.000sninu" wide //weight: 1
        $x_1_7 = "\"s%\" led &&2 n- 1.0.0.721 gnip c/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

