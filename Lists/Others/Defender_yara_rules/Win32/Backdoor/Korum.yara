rule Backdoor_Win32_Korum_A_2147652335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Korum.A"
        threat_id = "2147652335"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Korum"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 d2 8a 06 8a 56 01 31 c9 3c 0a 74 26 3c 0b 74 22 3c 0c 74 28 3c 0d 74 37}  //weight: 1, accuracy: High
        $x_1_2 = "software\\microsoft\\windows\\currentversion\\run" ascii //weight: 1
        $x_1_3 = "kz991nw33j2.txt" wide //weight: 1
        $x_1_4 = "lolo12aqsd45.txt" wide //weight: 1
        $x_1_5 = "69y278yh4-dfg,l243j8904jhkl;,i" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Korum_A_2147652335_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Korum.A"
        threat_id = "2147652335"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Korum"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Getting TASK file  from SERRVER" ascii //weight: 1
        $x_1_2 = "BODY update complite..." ascii //weight: 1
        $x_1_3 = "LINKS update complite..." ascii //weight: 1
        $x_1_4 = "kz991nw33j2.txt" ascii //weight: 1
        $x_1_5 = {50 4f 53 54 5f 44 49 52 45 43 54 ?? ?? ?? ?? ?? ?? ?? ?? ?? 54 41 53 4b 5f 49 44 00}  //weight: 1, accuracy: Low
        $x_1_6 = "MOZG_INTERVAL" ascii //weight: 1
        $x_1_7 = "/?LOG2777" ascii //weight: 1
        $x_1_8 = "/?c=DIR2777&p=" ascii //weight: 1
        $x_1_9 = "/?AS33322777" wide //weight: 1
        $x_1_10 = "ui3322jklot.txt" wide //weight: 1
        $x_1_11 = "iui89098uiopl.txt" wide //weight: 1
        $x_1_12 = "lolo12aqsd45.txt" wide //weight: 1
        $x_1_13 = "/SRV1/GTT/slave.cgi/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

