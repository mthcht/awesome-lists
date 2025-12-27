rule Trojan_MSIL_Quasarrat_RR_2147959018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasarrat.RR!MTB"
        threat_id = "2147959018"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasarrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 11 11 04 16 97 11 08 1f 29 95 6e 1e 6a d6 28 [0-5] 12 0c 28 [0-5] 28 [0-5] 1a 11 10 6f}  //weight: 1, accuracy: Low
        $x_1_2 = "cmd.exe" wide //weight: 1
        $x_1_3 = "Fiddler" wide //weight: 1
        $x_1_4 = "\\Programs\\Fiddler\\App.ico" wide //weight: 1
        $x_1_5 = "VirtualAllocEx" wide //weight: 1
        $x_1_6 = "NtGetContextThread" wide //weight: 1
        $x_1_7 = "NtUnmapViewOfSection" wide //weight: 1
        $x_1_8 = "NtResumeThread" wide //weight: 1
        $x_1_9 = "NtWriteVirtualMemory" wide //weight: 1
        $x_1_10 = "NtSetContextThread" wide //weight: 1
        $x_1_11 = "ping 1.1.1.1 -n 1 -w 3000 > Nul & Del" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasarrat_PGQR_2147959019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasarrat.PGQR!MTB"
        threat_id = "2147959019"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasarrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "qD2NalEvLm/YHMg4jQgJd35HeMETa6jEQdZP2aND1mO46sceGwzflWoth0L+7CsuyvjlLjvDw8MiS5EpyuNp5Mr45S47w8PDIkuRKcrjaeSQ/Cy1Pf8c/xGADKnzIT" ascii //weight: 5
        $x_5_2 = "1299.exe" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasarrat_PQ_2147959949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasarrat.PQ!MTB"
        threat_id = "2147959949"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasarrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 11 04 02 11 04 91 09 20 ff 00 00 00 5f 61 d2 9c 09 20 0d 66 19 00 5a 20 5f f3 6e 3c 58 0d 11 04 17 58 13 04 11 04 02 8e 69 32 d4}  //weight: 5, accuracy: High
        $x_2_2 = {00 00 0a 0a 06 16 73 ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 07 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 0d de 23}  //weight: 2, accuracy: Low
        $x_1_3 = {08 11 05 08 11 05 91 19 63 08 11 05 91 1b 62 60 d2 9c 11 05 17 58 13 05 11 05 08 8e 69 32 e1 08 28 ?? 00 00 0a 08 13 06 de 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

