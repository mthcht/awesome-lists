rule Backdoor_Win32_Netbot_C_2147600978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Netbot.C"
        threat_id = "2147600978"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Netbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "L9IW2QB23-CD-EDF-2-22d2-9CBD-00WSFS8AR6-9QER21QAJPM" ascii //weight: 20
        $x_1_2 = "\\mscidaemon.com" ascii //weight: 1
        $x_1_3 = "\\mscidaemon.exe" ascii //weight: 1
        $x_1_4 = "\\mscidaemon.dll" ascii //weight: 1
        $x_1_5 = "POP3 Password2" ascii //weight: 1
        $x_1_6 = "POP3 Server" ascii //weight: 1
        $x_1_7 = "POP3 User Name" ascii //weight: 1
        $x_1_8 = "HTTPMail Password2" ascii //weight: 1
        $x_1_9 = "Hotmail" ascii //weight: 1
        $x_1_10 = "HTTPMail User Name" ascii //weight: 1
        $x_1_11 = "Software\\Microsoft\\Internet Account Manager\\Accounts" ascii //weight: 1
        $x_1_12 = "Res Name:%s Res Type:%s User:%s Pass :%s" ascii //weight: 1
        $x_1_13 = "U:%s P :%s" ascii //weight: 1
        $x_1_14 = "AutoComp Pas" ascii //weight: 1
        $x_1_15 = "MSN Explorer Signup" ascii //weight: 1
        $x_1_16 = "OutExp" ascii //weight: 1
        $x_1_17 = "IE:Pas-Prot sites" ascii //weight: 1
        $x_1_18 = "EXPLORER.EXE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Netbot_D_2147656818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Netbot.D"
        threat_id = "2147656818"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Netbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {4e 42 56 69 70 2e 64 6c 6c 00}  //weight: 2, accuracy: High
        $x_2_2 = {8a 08 32 ca 02 ca 88 08 40 4e 75 f4}  //weight: 2, accuracy: High
        $x_2_3 = {43 41 4f 4e 49 4d 41 44 45 53 48 41 57 4f 00}  //weight: 2, accuracy: High
        $x_1_4 = {52 75 6e 55 6e 69 6e 73 74 61 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {4b 69 6c 6c 20 59 6f 75 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

