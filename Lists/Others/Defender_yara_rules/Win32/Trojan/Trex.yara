rule Trojan_Win32_Trex_A_2147717532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trex.A"
        threat_id = "2147717532"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Completed! All Files recovered!" wide //weight: 1
        $x_1_2 = {2e 00 7a 00 69 00 70 00 00 09 2e 00 6d 00 70 00 33 00 00 07 2e 00 37 00 7a 00 00 09 2e 00 72 00 61 00 72 00 00 09 2e 00 77 00 6d 00 61 00 00 09 2e 00 61 00 76 00 69 00 00 09 2e 00 77 00 6d 00}  //weight: 1, accuracy: High
        $x_1_3 = "STATUS: Files unlocked" wide //weight: 1
        $x_1_4 = "STATUS: Unlocking files..." wide //weight: 1
        $x_1_5 = "THE DONALD TRUMP RANSOMWARE" wide //weight: 1
        $x_1_6 = ".ENCRYPTED" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

