rule Trojan_Win32_Redcont_A_2147707476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redcont.A"
        threat_id = "2147707476"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redcont"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 01 6a 00 6a 00 6a 00 53 e8 ?? ?? ?? ?? 85 c0 74 e7 83 7b 04 12 0f 84}  //weight: 1, accuracy: Low
        $x_1_2 = {41 70 70 46 69 6c [0-2] 51 73 53 53 53 77 77 77 77}  //weight: 1, accuracy: Low
        $x_1_3 = "Mljkfblgjnslsdfngkjsdnfglk" ascii //weight: 1
        $x_1_4 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 62 6f [0-1] 74 6d 67 72 2e 69 6e 69}  //weight: 1, accuracy: Low
        $x_1_5 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 64 65 6c [0-1] 2e 74 78 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

