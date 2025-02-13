rule Trojan_Win32_Licat_A_2147692227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Licat.A"
        threat_id = "2147692227"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Licat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ASPROTECT UNPACKED BY AVP" ascii //weight: 1
        $x_1_2 = "C:\\Program Files\\Messenger\\msmsgs.exe\\3" ascii //weight: 1
        $x_1_3 = "333xxxxsssxxxxx3gg3333333" wide //weight: 1
        $x_1_4 = "funpic.org/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

