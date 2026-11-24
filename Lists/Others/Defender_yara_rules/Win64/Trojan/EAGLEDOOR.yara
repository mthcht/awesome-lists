rule Trojan_Win64_EAGLEDOOR_AMTB_2147982654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/EAGLEDOOR!AMTB"
        threat_id = "2147982654"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "EAGLEDOOR"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "D:\\record\\tzq\\workspace\\2022\\vok\\Door\\Bin\\HookDll.pdb" ascii //weight: 3
        $x_3_2 = "igol com file" ascii //weight: 3
        $x_3_3 = "igol product" ascii //weight: 3
        $x_2_4 = "My_CreateHookApiEx" ascii //weight: 2
        $x_2_5 = "My_QueueEnableHook" ascii //weight: 2
        $x_1_6 = "My_StatusToString" ascii //weight: 1
        $x_1_7 = "My_ApplyQueued" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

