rule Trojan_Win64_HadesRAT_LR_2147972218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/HadesRAT.LR!MTB"
        threat_id = "2147972218"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "HadesRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "45"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "msiexec.exe /quiet /qn /i \"%s\"" ascii //weight: 1
        $x_2_2 = "====== HadesRAT Debug Session Start ======" ascii //weight: 2
        $x_3_3 = "[RMMAP] injetando: pid=%lu dll=%zu bytes" ascii //weight: 3
        $x_4_4 = " binario stale ou linker removeu a secao." ascii //weight: 4
        $x_5_5 = "[RMMAP] alloc shellcode st=0x%08X" ascii //weight: 5
        $x_6_6 = "[RMMAP] write shellcode st=0x%08X" ascii //weight: 6
        $x_7_7 = "[RMMAP] inject OK pid=%lu" ascii //weight: 7
        $x_8_8 = " truncando a 64KB" ascii //weight: 8
        $x_9_9 = "[RMMAP]    -> se persistir: add /SECTION:.rmm,ERX em build_bin.py" ascii //weight: 9
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

