rule Trojan_Win32_Protob_B_2147741976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Protob.B"
        threat_id = "2147741976"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Protob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "winmgmts:\\\\.\\root\\SecurityCenter" wide //weight: 1
        $x_1_2 = "Select * from AntiVirusProduct" wide //weight: 1
        $x_1_3 = "Select * from FirewallProduct" wide //weight: 1
        $x_1_4 = "ten.timilorez.cri" wide //weight: 1
        $x_1_5 = "kll.bat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

