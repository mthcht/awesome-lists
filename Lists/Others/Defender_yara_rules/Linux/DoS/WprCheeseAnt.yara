rule DoS_Linux_WprCheeseAnt_A_2147965726_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Linux/WprCheeseAnt.A!dha"
        threat_id = "2147965726"
        type = "DoS"
        platform = "Linux: Linux platform"
        family = "WprCheeseAnt"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[*] Starting scan with " ascii //weight: 1
        $x_1_2 = "[*] Roots to scan: " ascii //weight: 1
        $x_1_3 = "[=] Scan complete in " ascii //weight: 1
        $x_1_4 = "[=] Directories traversed: " ascii //weight: 1
        $x_1_5 = "[=] Files found: " ascii //weight: 1
        $x_1_6 = "[=] Files scanned: " ascii //weight: 1
        $x_1_7 = "[=] Files failed: " ascii //weight: 1
        $x_1_8 = "[*] Traversal complete. Draining work queue..." ascii //weight: 1
        $x_1_9 = "[!] No disks found." ascii //weight: 1
        $x_1_10 = "[DISK]: " ascii //weight: 1
        $x_1_11 = "[*] Sleeping for " ascii //weight: 1
        $x_1_12 = " seconds..." ascii //weight: 1
        $x_1_13 = "[*] Enumerating system disks..." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

