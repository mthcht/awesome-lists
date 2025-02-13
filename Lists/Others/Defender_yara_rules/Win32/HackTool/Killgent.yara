rule HackTool_Win32_Killgent_DB_2147929258_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Killgent.DB!MTB"
        threat_id = "2147929258"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Killgent"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[+] Launching attack on ms01" ascii //weight: 1
        $x_1_2 = "[+] Moved policy successfully" ascii //weight: 1
        $x_1_3 = "[+] Rebooted target" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

