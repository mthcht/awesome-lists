rule Trojan_Win32_Gamafeshi_A_2147723944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gamafeshi.A"
        threat_id = "2147723944"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamafeshi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {44 47 4d 4e 4f 45 50 00}  //weight: 10, accuracy: High
        $x_10_2 = "%s - %s - %2.2x" wide //weight: 10
        $x_10_3 = {57 00 49 00 4e 00 57 00 4f 00 52 00 44 00 2e 00 45 00 58 00 45 00 00 00}  //weight: 10, accuracy: High
        $x_10_4 = {04 cd ab 34 12 75}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

