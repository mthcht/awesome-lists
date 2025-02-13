rule PWS_Win32_Hockus_A_2147651069_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Hockus.A"
        threat_id = "2147651069"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Hockus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c9 ff 33 c0 f2 ae f7 d1 83 c1 ff 89 4d cc c7 45 ec ff ff ff ff}  //weight: 1, accuracy: High
        $x_1_2 = "Password:" ascii //weight: 1
        $x_1_3 = {6e 65 74 73 68 22 20 66 69 72 65 77 61 6c 6c 20 61 64 64 20 70 6f 72 74 6f 70 65 6e 69 6e 67 20 54 43 50 20 00}  //weight: 1, accuracy: High
        $x_1_4 = "upgrade.txt?sign=" ascii //weight: 1
        $x_1_5 = "rbl.txt?sign=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

