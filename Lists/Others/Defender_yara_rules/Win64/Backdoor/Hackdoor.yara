rule Backdoor_Win64_Hackdoor_A_2147708413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Hackdoor.A!dll"
        threat_id = "2147708413"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Hackdoor"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\DosDevices\\kifes" ascii //weight: 1
        $x_1_2 = "\\Device\\kifes" ascii //weight: 1
        $x_1_3 = "hellohaha" ascii //weight: 1
        $x_1_4 = "ipfltdrv.sys" ascii //weight: 1
        $x_1_5 = "\\Device\\IPFILTERDRIVER" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Hackdoor_A_2147708413_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Hackdoor.A!dll"
        threat_id = "2147708413"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Hackdoor"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "The version of personal hacker's door server is" ascii //weight: 1
        $x_1_2 = "I'mhackeryythac1977" ascii //weight: 1
        $x_1_3 = {47 6c 6f 62 61 6c 5c 64 6f 6f 72 6e 65 65 64 73 68 75 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {68 6b 64 6f 6f 72 65 76 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {53 65 6c 6c 5f 44 45 53 4b 54 4f 50 00}  //weight: 1, accuracy: High
        $x_1_6 = {25 73 25 64 2e 25 64 20 53 45 51 3a 25 73 0d 0a 25 73 0d 0a 00}  //weight: 1, accuracy: High
        $x_1_7 = {44 6f 6d 61 69 6e 3a 25 53 2c 55 73 65 72 3a 25 53 2c 50 61 73 73 77 6f 72 64 3a 25 73 00}  //weight: 1, accuracy: High
        $x_1_8 = {70 72 65 61 70 72 65 20 74 6f 20 6c 6f 61 64 20 64 72 69 76 65 72 21 21 21 20 72 65 74 43 6f 64 65 3d 25 64 00}  //weight: 1, accuracy: High
        $x_1_9 = {48 b8 75 6e 6b 6e 6f 77 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

