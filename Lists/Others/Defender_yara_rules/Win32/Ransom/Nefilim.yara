rule Ransom_Win32_Nefilim_GM_2147754444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Nefilim.GM!MTB"
        threat_id = "2147754444"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Nefilim"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 1c 03 8b [0-16] 8a 14 01 8a 08 88 5d [0-21] 8a 1c 03 [0-100] 32 93 [0-48] 8a 1c 33 32 da [0-48] 32 d1 88 50 ?? 8a 0e 32 4d [0-16] 88 4e [0-37] 32 4d [0-16] 88 0f}  //weight: 1, accuracy: Low
        $x_1_2 = "/c WmIc ShaDowcoPY delEte" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Nefilim_PA_2147757433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Nefilim.PA!MTB"
        threat_id = "2147757433"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Nefilim"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TELEGRAM-RECOVER.txt" wide //weight: 1
        $x_1_2 = ".TELEGRAM" wide //weight: 1
        $x_1_3 = "\\GOOBA.jpg" wide //weight: 1
        $x_1_4 = "\\sosat' kiki\\devka\\Release\\TELEGRAM.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

