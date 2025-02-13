rule Backdoor_Win32_Matchaldru_D_2147657047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Matchaldru.D"
        threat_id = "2147657047"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Matchaldru"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "140.112.19.195" ascii //weight: 1
        $x_1_2 = "search5%d" ascii //weight: 1
        $x_1_3 = "&h4=" ascii //weight: 1
        $x_1_4 = "Mozilla/5" ascii //weight: 1
        $x_1_5 = {b2 64 b1 25}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Matchaldru_E_2147690178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Matchaldru.E!dha"
        threat_id = "2147690178"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Matchaldru"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "search5%d?" ascii //weight: 1
        $x_1_2 = "=%s&h4=%s" ascii //weight: 1
        $x_1_3 = {b2 64 b1 25}  //weight: 1, accuracy: High
        $x_1_4 = {33 d2 8a c3 c0 e8 04 04 41 0f be c8 51}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

