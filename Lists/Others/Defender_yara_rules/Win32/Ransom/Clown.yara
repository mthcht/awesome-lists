rule Ransom_Win32_Clown_A_2147749489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Clown.A!MSR"
        threat_id = "2147749489"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Clown"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "bg.txt.clown" ascii //weight: 1
        $x_1_2 = "!!! READ THIS !!!.hta" ascii //weight: 1
        $x_1_3 = "HOW TO RECOVER ENCRYPTED FILES.txt" ascii //weight: 1
        $x_1_4 = {5c 54 68 65 44 4d 52 5f 45 6e 63 72 79 70 74 65 72 5c [0-16] 5c 54 68 65 44 4d 52 5f 45 6e 63 72 79 70 74 65 72 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Clown_AA_2147756632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Clown.AA!MTB"
        threat_id = "2147756632"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Clown"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "CLOWN RANSOMWARE" ascii //weight: 10
        $x_5_2 = "All personal files on your computer are encrypted!" ascii //weight: 5
        $x_5_3 = "HOW TO RECOVER ENCRYPTED FILES.txt" ascii //weight: 5
        $x_5_4 = "you have to pay in Bitcoin" ascii //weight: 5
        $x_2_5 = "AdminEnc@Protonmail.com" ascii //weight: 2
        $x_2_6 = "DecryptAdmin@prtonmail.com" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*))) or
            (all of ($x*))
        )
}

