rule Backdoor_Win32_Mobibez_A_2147606488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mobibez.gen!A"
        threat_id = "2147606488"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mobibez"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BioZombie_Virus" ascii //weight: 1
        $x_1_2 = "\\BIOZOMBIE\\Server\\" wide //weight: 1
        $x_1_3 = "c:\\windows\\system\\Update.exe" wide //weight: 1
        $x_1_4 = "Icmp Attacking..." wide //weight: 1
        $x_1_5 = "UDP Attacking..." wide //weight: 1
        $x_1_6 = "Attack Stopped..." wide //weight: 1
        $x_1_7 = "|DRVS|" wide //weight: 1
        $x_1_8 = "|FILESIZE|" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

