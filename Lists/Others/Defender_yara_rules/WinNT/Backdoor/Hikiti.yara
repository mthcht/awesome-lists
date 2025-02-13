rule Backdoor_WinNT_Hikiti_A_2147693124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Hikiti.A!dha"
        threat_id = "2147693124"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Hikiti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "imagename found at:%s" ascii //weight: 1
        $x_2_2 = "hide---port = %d" ascii //weight: 2
        $x_2_3 = {2d 2d 2d 68 69 64 65 [0-64] 2e 64 61 74 61}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_WinNT_Hikiti_A_2147693127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Hikiti.gen.A!dha"
        threat_id = "2147693127"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Hikiti"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 77 00 37 00 66 00 77 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "ETag: \"%x%x%x:%03x\"" ascii //weight: 1
        $x_1_3 = {3a 5c 53 6f 75 72 63 65 43 6f 64 65 5c 48 69 6b 69 74 5f 6e 65 77 5c 62 69 6e 33 32 5c 77 37 66 77 [0-4] 2e 70 64 62 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

