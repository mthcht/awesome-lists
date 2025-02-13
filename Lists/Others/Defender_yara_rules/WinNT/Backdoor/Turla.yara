rule Backdoor_WinNT_Turla_B_2147691957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Turla.B!dha"
        threat_id = "2147691957"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Turla"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "token_val" ascii //weight: 1
        $x_1_2 = "filter_c06b1a3b" wide //weight: 1
        $x_1_3 = "NdisFRegisterFilterDriver" ascii //weight: 1
        $x_1_4 = "FwpsStreamInjectAsync0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_WinNT_Turla_A_2147691972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Turla.A!dha"
        threat_id = "2147691972"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Turla"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 01 4c 24 10 8b 44 24 12 0f b7 48 06 0f b7 00 c1 e1 10 0b c8 51 e8}  //weight: 1, accuracy: High
        $x_1_2 = {76 1b 8a 04 0e 88 04 0f 6a 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_WinNT_Turla_C_2147691973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Turla.C!dha"
        threat_id = "2147691973"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Turla"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "NdisFRegisterFilterDriver" ascii //weight: 1
        $x_1_2 = "FwpmCalloutAdd0" ascii //weight: 1
        $x_1_3 = "\\BaseNamedObjects\\{c2b99b50-5bf2-4c81-90d3-6c6c82ba5111}" ascii //weight: 1
        $x_1_4 = {48 8d 4c 24 40 33 d2 41 b8 04 01 00 00 e8 ?? ?? ?? ?? 44 8b 5f 30 4c 8d 0d ?? ?? ?? ?? 4c 8d 05 ?? ?? ?? ?? 48 8d 4c 24 40 ba 03 01 00 00 44 89 5c 24 20 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

