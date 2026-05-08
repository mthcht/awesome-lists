rule Ransom_Win64_Gentlemen_A_2147954278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Gentlemen.A"
        threat_id = "2147954278"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Gentlemen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "README-GENTLEMEN.txt" ascii //weight: 1
        $x_1_2 = "--marker--" ascii //weight: 1
        $x_1_3 = {5b 57 25 21 64 28 4d 49 53 53 49 4e 47 29 5d 20 45 52 52 4f 52 20 25 21 73 28 4d 49 53 53 49 4e 47 29 20 3a 20 25 21 76 28 4d 49 53 53 49 4e 47 29 0a}  //weight: 1, accuracy: High
        $x_1_4 = "LOCKER_BACKGROUND=1" ascii //weight: 1
        $x_1_5 = {5b 2b 5d 20 d0 9d d0 b0 d1 87 d0 b0 d1 82 d0 be 20 d1 88 d0 b8 d1 84 d1 80 d0 be d0 b2 d0 b0 d0 bd d0 b8 d0 b5 2e 20 d0 a3 d1 85 d0 be d0 b4 d0 b8 d0 bc 20 d0 b2 20 d1 84 d0 be d0 bd 2e 2e 2e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win64_Gentlemen_B_2147962326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Gentlemen.B"
        threat_id = "2147962326"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Gentlemen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "README-GENTLEMEN.txt" ascii //weight: 1
        $x_1_2 = "Error: --shares and --system cannot be used together." ascii //weight: 1
        $x_1_3 = "Lateral movement: domain/user:password (optional)" ascii //weight: 1
        $x_1_4 = "[+] Encryption started. Going background..." ascii //weight: 1
        $x_1_5 = "gentlemen.bmp" ascii //weight: 1
        $x_1_6 = "gentlemen_system" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_Win64_Gentlemen_SH_2147968830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Gentlemen.SH!MTB"
        threat_id = "2147968830"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Gentlemen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 29 d7 48 89 7c 24 ?? 48 f7 df 48 c1 ff ?? 48 21 d7 4c 8b 84 24 ?? ?? ?? ?? 45 8b 48 ?? 41 69 d9 ?? ?? ?? ?? 41 33 18 48 29 d1 48 89 4c 24 ?? 48 8d 0c 3e 48 89 8c 24 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = "gentlemen.bmp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

