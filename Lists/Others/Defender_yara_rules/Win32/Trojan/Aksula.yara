rule Trojan_Win32_Aksula_C_2147655397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Aksula.C"
        threat_id = "2147655397"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Aksula"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "SOFTWARE\\SaKuLa Keymake\\" ascii //weight: 5
        $x_1_2 = "rundll32.exe url.dll,FileProtocolHandler" ascii //weight: 1
        $x_3_3 = {ff 15 38 a0 40 00 90 90 90 90 39 65 e8 74 0d 68 06 00 00 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

