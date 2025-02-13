rule Backdoor_Win32_Simbot_2147647031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Simbot"
        threat_id = "2147647031"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Simbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {56 8b 45 0c 8d 8d e8 fe ff ff 8d 34 03 e8 ?? ?? ?? ?? 30 06 43 3b 5d 10 7c e7 5e}  //weight: 2, accuracy: Low
        $x_1_2 = "/%s.php?id=%06d%s" ascii //weight: 1
        $x_1_3 = "%c%c%c%c%c%c.exe" ascii //weight: 1
        $x_1_4 = "%02X-%02X-%02X-%02X-%02X-%02X" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Simbot_2147648241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Simbot"
        threat_id = "2147648241"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Simbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {2f 66 63 2e c7 45 ?? 61 73 70 3f c7 45 ?? 65 73 74 3d c7 45 fc ?? 00 cc cc}  //weight: 15, accuracy: Low
        $x_5_2 = "\\ntuser.cfg\",Config" ascii //weight: 5
        $x_5_3 = "%02x-%02x-%02x-%02x-%02x-%02x" ascii //weight: 5
        $x_5_4 = "%s%s%s&hn%s%s &ha%s%s &hm%s%s &hv%s%s &hb%s%s &hp%s%s" ascii //weight: 5
        $x_1_5 = "sophos" ascii //weight: 1
        $x_1_6 = "kaspersky" ascii //weight: 1
        $x_1_7 = "trend" ascii //weight: 1
        $x_1_8 = "panda" ascii //weight: 1
        $x_1_9 = "macfee" ascii //weight: 1
        $x_1_10 = "symantec" ascii //weight: 1
        $x_1_11 = "norton" ascii //weight: 1
        $x_1_12 = "avira" ascii //weight: 1
        $x_1_13 = "avast" ascii //weight: 1
        $x_1_14 = "360sd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_15_*) and 2 of ($x_5_*) and 10 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_5_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

