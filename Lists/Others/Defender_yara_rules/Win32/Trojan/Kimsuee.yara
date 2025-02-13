rule Trojan_Win32_Kimsuee_A_2147735788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kimsuee.A"
        threat_id = "2147735788"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kimsuee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe\" \"%s\" installsvc" ascii //weight: 1
        $x_1_2 = "_MY_BABY_" ascii //weight: 1
        $x_1_3 = "http://yuseung.elimbiz.com/sub/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

