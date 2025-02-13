rule Trojan_Win32_Frgnrns_A_2147740888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Frgnrns.A!MTB"
        threat_id = "2147740888"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Frgnrns"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[!]Cant get cpu name." ascii //weight: 1
        $x_1_2 = "[!]Error getting memory." ascii //weight: 1
        $x_1_3 = "[!]Cant get process names." ascii //weight: 1
        $x_1_4 = "Alredy running" ascii //weight: 1
        $x_1_5 = "[!] WSAStartup error: %i" ascii //weight: 1
        $x_1_6 = "[+] Connect to Server success" ascii //weight: 1
        $x_1_7 = "[+]Command stop reverse proxy." ascii //weight: 1
        $x_1_8 = "[+]Command start reverse proxy." ascii //weight: 1
        $x_1_9 = "[!]Reverse proxy already started" ascii //weight: 1
        $x_1_10 = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\" ascii //weight: 1
        $x_1_11 = "[!] Connect to Server error" ascii //weight: 1
        $x_1_12 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_13 = "SomeKey" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (12 of ($x*))
}

