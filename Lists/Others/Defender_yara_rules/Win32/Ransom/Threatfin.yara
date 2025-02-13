rule Ransom_Win32_Threatfin_A_2147694512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Threatfin.A"
        threat_id = "2147694512"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Threatfin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 e8 57 00 49 00 c7 45 ec 4e 00 55 00 c7 45 f0 50 00 00 00 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 f0 55 00 41 00 c7 45 f4 50 00 20 00 c7 45 f8 44 00 75 00}  //weight: 1, accuracy: High
        $x_1_3 = ".blockchain.info/en/wallet" ascii //weight: 1
        $x_1_4 = {42 00 72 00 6f 00 77 00 73 00 65 00 72 00 00 00 5c 00 48 00 45 00 4c 00 50 00 5f 00 44 00 45 00 43 00 52 00 59 00 50 00 54 00 2e 00 48 00 54 00 4d 00 4c 00}  //weight: 1, accuracy: High
        $x_1_5 = {6f 00 70 00 65 00 6e 00 00 00 00 00 2a 00 2e 00 74 00 78 00 74 00 00 00 2a 00 2e 00 68 00 74 00 6d 00 6c 00}  //weight: 1, accuracy: High
        $x_1_6 = "Threat Finder" ascii //weight: 1
        $x_1_7 = "files will be lost forever!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

