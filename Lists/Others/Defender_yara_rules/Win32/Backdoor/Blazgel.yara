rule Backdoor_Win32_Blazgel_A_2147607548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Blazgel.A"
        threat_id = "2147607548"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Blazgel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {b9 5a 36 c4 01 b8 e2 df 59 38 89 4c 24 3c 89 4c 24 34 89 4c 24 2c 8d 4c 24 28 89 44 24 38 89 44 24 30 89 44 24 28 8d 54 24 30 51 8d 44 24 3c 52 50 53 c7 44 24 3c c2 27 c5 01 ff 15}  //weight: 3, accuracy: High
        $x_3_2 = {8d 14 92 d1 e2 48 75 f8 8b fd 83 c9 ff 33 c0 f2 ae b8 1f 85 eb 51 8b 7c 24 10 f7 ea f7 d1 49 c1 fa 05 0f be 0c 19 8b c2 83 e9 30 c1 e8 1f 03 d0 0f af ca 03 f9 4e 43}  //weight: 3, accuracy: High
        $x_1_3 = "\\del.bat" ascii //weight: 1
        $x_1_4 = "\\\\.\\usbmouseb" ascii //weight: 1
        $x_1_5 = "%s -r \"%s" ascii //weight: 1
        $x_1_6 = "LoadRootKit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Blazgel_A_2147607549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Blazgel.A"
        threat_id = "2147607549"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Blazgel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {68 38 02 00 00 50 ?? ?? c7 84 24 ?? 02 00 00 88 88 88 88 c7 84 24 ?? 02 00 00 38 02 00 00 ff ?? 85 c0}  //weight: 5, accuracy: Low
        $x_2_2 = "BLAZINGANGELRUNNING" ascii //weight: 2
        $x_2_3 = "\\\\.\\usbmouseb" ascii //weight: 2
        $x_1_4 = "VIP-NV(200" ascii //weight: 1
        $x_1_5 = "HEART_BEAT %s %d" ascii //weight: 1
        $x_1_6 = "+OK LISTDRV" ascii //weight: 1
        $x_1_7 = "%s -o %s %d" ascii //weight: 1
        $x_1_8 = "USERID=%s,CAP=%d,LOGIN=%s,DOCMD=%d,HOSTNAME=%s,OS=%s" ascii //weight: 1
        $x_1_9 = "555 PASSWORD=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

