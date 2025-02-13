rule Backdoor_Win32_Cocoazul_A_2147602392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Cocoazul.gen!A"
        threat_id = "2147602392"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Cocoazul"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "%02d/%02d/%04d %02d:%02d:%02d" ascii //weight: 10
        $x_10_2 = {25 31 64 00 5b 4c 5d 00 5b 52 5d 00 5b 4d 5d 00}  //weight: 10, accuracy: High
        $x_10_3 = {0d 0a 4c 6f 67 20 53 74 6f 70 70 65 64 0d 0a}  //weight: 10, accuracy: High
        $x_10_4 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Hotfix\\Q246009" ascii //weight: 10
        $x_10_5 = "Software\\Microsoft\\Internet Account Manager\\Accounts" ascii //weight: 10
        $x_10_6 = "\\drivers\\etc\\hosts" ascii //weight: 10
        $x_10_7 = {49 45 3a 50 50 53 00}  //weight: 10, accuracy: High
        $x_10_8 = {4d 53 4e 00}  //weight: 10, accuracy: High
        $x_10_9 = {48 6f 74 6d 61 69 6c 00}  //weight: 10, accuracy: High
        $x_1_10 = "www.f-secure.com" ascii //weight: 1
        $x_1_11 = "www.kaspersky.com" ascii //weight: 1
        $x_1_12 = "www.symantec.com" ascii //weight: 1
        $x_1_13 = "www.mcafee.com" ascii //weight: 1
        $x_1_14 = "Datacenter Server" ascii //weight: 1
        $x_1_15 = "Standard Edition" ascii //weight: 1
        $x_1_16 = "Web Edition" ascii //weight: 1
        $x_1_17 = "Enterprise Edition" ascii //weight: 1
        $x_1_18 = {48 54 54 50 4d 61 69 6c 20 50 61 73 73 77 6f 72 64 32 00}  //weight: 1, accuracy: High
        $x_1_19 = {48 54 54 50 4d 61 69 6c 20 55 73 65 72 20 4e 61 6d 65 00}  //weight: 1, accuracy: High
        $x_1_20 = {50 4f 50 33 20 50 61 73 73 77 6f 72 64 32 00}  //weight: 1, accuracy: High
        $x_1_21 = {50 4f 50 33 20 55 73 65 72 20 4e 61 6d 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((9 of ($x_10_*) and 10 of ($x_1_*))) or
            (all of ($x*))
        )
}

