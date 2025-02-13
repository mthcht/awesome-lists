rule Trojan_Win32_Sessa_A_2147735432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sessa.A"
        threat_id = "2147735432"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sessa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\system32\\777.dll" ascii //weight: 1
        $x_1_2 = "clsid\\{083863f1-70de-11d0-bd40-00a0c911ce86}\\instance\\{129d7e40-c10d-11d0-afb9-00aa00b67a42}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

