rule Tampering_Win32_Bitis_A_2147958168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Tampering:Win32/Bitis.A"
        threat_id = "2147958168"
        type = "Tampering"
        platform = "Win32: Windows 32-bit platform"
        family = "Bitis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[-] Cannot open driver device, exiting." wide //weight: 1
        $x_1_2 = "[+] Killed %ls (pid %lu)" wide //weight: 1
        $x_1_3 = "[*] Looping. Press Ctrl+C to stop." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

