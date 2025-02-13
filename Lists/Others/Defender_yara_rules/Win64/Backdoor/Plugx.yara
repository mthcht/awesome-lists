rule Backdoor_Win64_Plugx_A_2147694041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Plugx.A!dha"
        threat_id = "2147694041"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Plugx"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "line=%d error=%d" ascii //weight: 1
        $x_1_2 = "Version: major:%d, minor:%d" ascii //weight: 1
        $x_1_3 = "found service_record table!" ascii //weight: 1
        $x_1_4 = {ba 2a 00 00 00 48 8d 0d 81 0b 00 00 ff 15 43 0b 00 00 ff 15 e5 0a 00 00 44 8b c0 ba 2b 00 00 00 48 8d 0d 66 0b 00 00 ff 15 28 0b 00 00 90 e9 6f 02 00 00 48 8b 54 24 48 48 8d 8c 24 c0 01 00 00 e8 d8 fd ff ff 8b f8 85 c0 74 3e ff 15 ac 0a 00 00 44 8b c0 ba 32 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {ba 56 00 00 00 48 8d 0d 69 09 00 00 ff 15 2b 09 00 00 ff 15 cd 08 00 00 44 8b c0 ba 57 00 00 00 48 8d 0d 4e 09 00 00 ff 15 10 09 00 00 bb 32 00 00 00 eb 1d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Plugx_2147705913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Plugx"
        threat_id = "2147705913"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Plugx"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_TeamViewer_Monitor" wide //weight: 1
        $x_1_2 = "SOFTWARE\\param" wide //weight: 1
        $x_1_3 = "OnLinePid" wide //weight: 1
        $x_1_4 = "\\AppCompatFlags\\Custom\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

