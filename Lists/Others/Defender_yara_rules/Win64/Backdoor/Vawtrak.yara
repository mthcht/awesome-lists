rule Backdoor_Win64_Vawtrak_A_2147681338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Vawtrak.A"
        threat_id = "2147681338"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Vawtrak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "[VNC] Start Sever" ascii //weight: 1
        $x_1_2 = "this.GetXHR=function(){\"undefined\"" ascii //weight: 1
        $x_1_3 = {48 83 c1 08 e8 ?? ?? ?? ?? f7 d8 1b c9 f7 d9 81 c1 fe 00 00 00 89 4b 04 eb ?? c7 41 04 ff 00 00 00 48 83 c1 08 ba 05 00 00 00 ff 15 ?? ?? ?? ?? eb ?? c7 41 04 ff 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {c1 c8 03 69 c0 fd 43 03 00 41 bf c3 9e 26 00 be 00 00 ff 7f 41 03 c7 44 8b e0 89 ?? ?? ?? ?? ?? 44 23 e6 85 c0 75 ?? ff 15 ?? ?? ?? ?? c1 c8 03 69 c0 fd 43 03 00 41 bd ff 7f 00 00 41 03 c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Vawtrak_A_2147681338_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Vawtrak.A"
        threat_id = "2147681338"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Vawtrak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "id=%0.8X%0.8X%0.8X%0.8X" ascii //weight: 1
        $x_1_2 = "info=%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.4X%0.2X%0.4X" ascii //weight: 1
        $x_1_3 = "~%0.4x%0.4x%0.4x" ascii //weight: 1
        $x_1_4 = "[%0.2u:%0.2u:%0.2u]" ascii //weight: 1
        $x_1_5 = "/showthread.php?t=%u" ascii //weight: 1
        $x_1_6 = "/newthread.php?do=postthread&f=%u" ascii //weight: 1
        $x_1_7 = "/newreply.php?do=postreply&t=%u" ascii //weight: 1
        $x_3_8 = {83 38 02 74 05 83 38 04 75 53 81 3a 47 45 54 20 75 08 41 b9 01 00 00 00 eb 24 81 3a 50 55 54 20 75 08 41 b9 03 00 00 00 eb 14 81 3a 50 4f 53 54 75 2b 80 7a 04 20 75 25}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win64_Vawtrak_C_2147707515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Vawtrak.C"
        threat_id = "2147707515"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Vawtrak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 01 6d 4e c6 41 05 39 30 00 00 89 01}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 74 24 60 85 db 74 16 80 3e 4d 75 06 80 7e 01 5a 74 1f}  //weight: 1, accuracy: High
        $x_1_3 = {32 03 48 ff c3 88 06 48 ff c6 49 ff ce 75 e7}  //weight: 1, accuracy: High
        $x_1_4 = {42 8a 04 09 41 32 c2 45 03 d0 41 ff c0 41 88 01 49 ff c1 41 83 f8 10 72 e7}  //weight: 1, accuracy: High
        $x_1_5 = "regsvr32.exe /s /i:\"%s\" \"%s" ascii //weight: 1
        $x_1_6 = "PID: %u [%0.2u:%0.2u:%0.2u]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

