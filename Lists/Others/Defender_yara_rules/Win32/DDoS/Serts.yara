rule DDoS_Win32_Serts_A_2147717834_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Win32/Serts.A"
        threat_id = "2147717834"
        type = "DDoS"
        platform = "Win32: Windows 32-bit platform"
        family = "Serts"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BANGLADESH BLACK HAT HACKERS DoS Attacker" ascii //weight: 1
        $x_1_2 = "*\\AD:\\Software\\Hacking Tools\\DDOS tools\\STRESS\\BBHH-DoS\\Project1.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

