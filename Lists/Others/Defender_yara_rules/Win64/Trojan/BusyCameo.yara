rule Trojan_Win64_BusyCameo_A_2147966704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BusyCameo.A"
        threat_id = "2147966704"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BusyCameo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Display K7RKScan" ascii //weight: 1
        $x_1_2 = "[*] Service already exists, cleaning up..." ascii //weight: 1
        $x_1_3 = "[+] CreateService Success" ascii //weight: 1
        $x_1_4 = "[!] Scanning for AV/EDR processes..." ascii //weight: 1
        $x_1_5 = "[*] No security processes detected" ascii //weight: 1
        $x_1_6 = "[!] Total processes terminated:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

