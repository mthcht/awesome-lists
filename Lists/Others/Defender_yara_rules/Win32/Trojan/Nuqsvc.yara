rule Trojan_Win32_Nuqsvc_A_2147695424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nuqsvc.A"
        threat_id = "2147695424"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nuqsvc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = "UrlGet" wide //weight: 4
        $x_10_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 32 00 32 00 32 00 2e 00 31 00 38 00 37 00 2e 00 [0-16] 3a 00 36 00 31 00}  //weight: 10, accuracy: Low
        $x_1_3 = "\\Explorer\\HideDesktopIcons\\NewStartPanel" wide //weight: 1
        $x_1_4 = "{871C5380-42A0-1069-A2EA-08002B30309D}\\shell\\OpenHomePage\\Command" wide //weight: 1
        $x_1_5 = {4c 6f 63 6b 49 45 00}  //weight: 1, accuracy: High
        $x_1_6 = {4c 6f 63 6b 53 74 61 72 74 50 61 67 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {43 68 61 6e 67 65 48 6f 73 74 73 00}  //weight: 1, accuracy: High
        $x_1_8 = {4c 6f 63 6b 44 6e 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

