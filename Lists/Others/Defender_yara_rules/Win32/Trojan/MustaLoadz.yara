rule Trojan_Win32_MustaLoadz_2147920410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MustaLoadz!MTB"
        threat_id = "2147920410"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MustaLoadz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 fa 4f 1b 4c 91 22 04 ab 48 4e 46 8e 74 33 a3 4e 4a 4c da 7e 62 aa 4d 49 49 85 70 37 ab 4c 47 1b db 70 67 a5 4b 4f 1c 84 73 67 ae 1b 4c 1c dc 47 37 a8 4e 46 4e 80 70 3c 91 4a 4c 1d 81 21 34 93 49 49 4d 81 74 32 91 47 1b 1c 81 24 3d 97 4f 1c 4a 95 24 35 c0 4c 1c 1b c9}  //weight: 1, accuracy: High
        $x_1_2 = "\\??\\C:\\Windows\\system32\\schtasks.exe" ascii //weight: 1
        $x_1_3 = {83 c4 04 6a 40 68 00 30 00 00 68 20 34 00 00 6a 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

