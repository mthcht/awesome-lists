rule HackTool_Win64_EDRSandblast_E_2147910973_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/EDRSandblast.E"
        threat_id = "2147910973"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "EDRSandblast"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[+] [ProcessProtection] Found the handle of the current process (PID: %hu): 0x%hx at 0x%I64x" wide //weight: 1
        $x_1_2 = "[+] Vulnerable driver is already running!" wide //weight: 1
        $x_1_3 = "[!] Couldn't allocate memory to enumerate the drivers in Kernel callbacks" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win64_EDRSandblast_F_2147912417_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/EDRSandblast.F"
        threat_id = "2147912417"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "EDRSandblast"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[!] ERROR ServiceInstall ; OpenSCManager(create) (0x%08x)" wide //weight: 1
        $x_1_2 = "[+] '%s' service ACL configured to for Everyone" wide //weight: 1
        $x_1_3 = "[!] ERROR ServiceUninstall ; ServiceUninstall (0x%08x)" wide //weight: 1
        $x_1_4 = "[*] '%s' service cannot accept control messages at this time, waiting..." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win64_EDRSandblast_G_2147928024_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/EDRSandblast.G"
        threat_id = "2147928024"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "EDRSandblast"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[+] Checking if EDR callbacks are registered on I/O events (minifilters)..." wide //weight: 1
        $x_1_2 = "[+] Process is \"safe\" to launch our payload" wide //weight: 1
        $x_1_3 = "[-] Downloading offsets from the internet failed !" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

