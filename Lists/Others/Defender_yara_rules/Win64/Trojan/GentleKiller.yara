rule Trojan_Win64_GentleKiller_AB_2147972186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GentleKiller.AB!MTB"
        threat_id = "2147972186"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GentleKiller"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=== EA JAVELIN AntiCheat ===" ascii //weight: 1
        $x_1_2 = "[+] D dropped successfully" ascii //weight: 1
        $x_1_3 = "[+] Starting monitoring loop..." ascii //weight: 1
        $x_1_4 = "[+] D loaded" ascii //weight: 1
        $x_1_5 = "[+] D already exists" ascii //weight: 1
        $x_1_6 = "[+] Cleanup complete" ascii //weight: 1
        $x_1_7 = "[-] Snapshot failed!" ascii //weight: 1
        $x_1_8 = "[+] Found SYS, PID: %lu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

