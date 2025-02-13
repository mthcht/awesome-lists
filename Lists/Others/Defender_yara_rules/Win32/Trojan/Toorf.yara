rule Trojan_Win32_Toorf_A_2147719553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Toorf.A!dha"
        threat_id = "2147719553"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Toorf"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/SaveFile?commandId=" wide //weight: 1
        $x_1_2 = "/CheckConnection" ascii //weight: 1
        $x_1_3 = "\\ddd\\a1.txt" wide //weight: 1
        $x_1_4 = "|||Command executed successfully" ascii //weight: 1
        $x_1_5 = {5c 42 6f 74 20 46 72 65 73 68 2e 70 64 62 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Toorf_B_2147719554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Toorf.B!dha"
        threat_id = "2147719554"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Toorf"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Start Keylog Done" wide //weight: 1
        $x_1_2 = "/SF?commandId=CmdResult=" wide //weight: 1
        $x_1_3 = "CreateMimi2Bat" ascii //weight: 1
        $x_1_4 = "|||Command executed successfully" ascii //weight: 1
        $x_1_5 = "\\Microsoft\\Windows\\Tmp*\" & rmdir \"" ascii //weight: 1
        $x_2_6 = {5c 42 6f 74 [0-16] 5c 49 73 6d 2e 70 64 62 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

