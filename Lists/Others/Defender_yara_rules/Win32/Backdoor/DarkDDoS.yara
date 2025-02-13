rule Backdoor_Win32_DarkDDoS_A_2147632608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/DarkDDoS.A"
        threat_id = "2147632608"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkDDoS"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "DaRK DDoSeR v" wide //weight: 3
        $x_3_2 = "Status: [ Icmp - Attack Enabled ]" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

