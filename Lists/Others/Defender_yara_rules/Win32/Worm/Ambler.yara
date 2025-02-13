rule Worm_Win32_Ambler_A_2147630319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Ambler.A"
        threat_id = "2147630319"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Ambler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b fe 80 71 ff ?? 80 31 ?? 80 71 01 ?? 83 c1 03 83 c2 03 8d 1c 0f 3b d8 72 e8}  //weight: 5, accuracy: Low
        $x_5_2 = {84 00 00 00 c7 05 ?? ?? ?? ?? 00 03 00 00 ff 15 ?? ?? ?? ?? b8 ?? ?? ?? ?? 8b c8 85 c9 74 10 6a 10 50 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 0c ?? ff 15 ?? ?? ?? ?? eb}  //weight: 5, accuracy: Low
        $x_5_3 = {6a 02 c6 06 4d 58 c6 46 01 5a 3b f8 76 09 80 34 30 ?? 40 3b c7 72 f7}  //weight: 5, accuracy: Low
        $x_2_4 = "**FORM**%s" ascii //weight: 2
        $x_2_5 = "name=\"securityKey%d\"" ascii //weight: 2
        $x_2_6 = "id=\"securityKey%dAns\"" ascii //weight: 2
        $x_2_7 = "%s=KEYLOGGED:%s KEYSREAD:%s" ascii //weight: 2
        $x_2_8 = "%s=KEYSREAD:%s" ascii //weight: 2
        $x_1_9 = "&kav;" ascii //weight: 1
        $x_1_10 = "logwords" ascii //weight: 1
        $x_1_11 = "LOADXML" ascii //weight: 1
        $x_1_12 = "HOSTADD" ascii //weight: 1
        $x_1_13 = "DELETESELF" ascii //weight: 1
        $x_1_14 = "DELETECOOKIES" ascii //weight: 1
        $x_1_15 = "COPYBOFAKEYS" ascii //weight: 1
        $x_1_16 = "DELETEBOFAKEYS" ascii //weight: 1
        $x_1_17 = "KILLWIN" ascii //weight: 1
        $x_1_18 = "RESETGRABLIMITS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_2_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Ambler_B_2147654676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Ambler.B"
        threat_id = "2147654676"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Ambler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {24 f8 50 56 ff 15 ?? ?? ?? ?? 56 ff 15 0c 00 be ?? ?? ?? ?? 56 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 01 5f 8d 4b 01 2b fb 0f be 51 ff 8a c2 03 75 fc f6 d0 32 c2 24 ?? f6 d2 32 c2 88 41 ff}  //weight: 1, accuracy: Low
        $x_1_3 = "\\Active Setup\\Installed Components\\" ascii //weight: 1
        $x_1_4 = "***GRABBED BALANCE****" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

