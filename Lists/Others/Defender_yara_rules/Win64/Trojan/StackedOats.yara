rule Trojan_Win64_StackedOats_A_2147959427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StackedOats.A!dha"
        threat_id = "2147959427"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StackedOats"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[-] DebugActiveProcess failed: %lu" ascii //weight: 1
        $x_1_2 = "[-] Origin Bytes Read failed" ascii //weight: 1
        $x_1_3 = "[-] Failed to Insert Breakpoint" ascii //weight: 1
        $x_1_4 = "[+] Monitoring Power Status ... " ascii //weight: 1
        $x_1_5 = "ShutdownConfirmation" ascii //weight: 1
        $x_1_6 = "Shutdown or Restart!!!!!" ascii //weight: 1
        $x_1_7 = "[+] Found memcpy in IAT! Address: 0x%p" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

