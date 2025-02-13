rule Backdoor_Win32_Drateam_A_2147619074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Drateam.gen!A"
        threat_id = "2147619074"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Drateam"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff ff ff ff 0f 00 00 00 4d 53 47 7c c4 bf c2 bc b2 bb b4 e6 d4 da 21 00}  //weight: 1, accuracy: High
        $x_1_2 = {ff ff ff ff 0d 00 00 00 4d 53 47 7c ce de b7 a8 bb f1 c8 a1 21 00}  //weight: 1, accuracy: High
        $x_1_3 = {d4 ca d0 ed b4 cb b6 af d7 f7 00}  //weight: 1, accuracy: High
        $x_1_4 = {ff ff ff ff 07 00 00 00 65 78 65 2e 70 76 61}  //weight: 1, accuracy: High
        $x_1_5 = {ff ff ff ff 0c 00 00 00 65 78 65 2e 6e 72 6b 32 33 64 6f 6e}  //weight: 1, accuracy: High
        $x_1_6 = {68 01 02 00 00 ?? e8 ?? ?? ?? ?? 6a 00 6a 00 68 02 02 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Win32_Drateam_B_2147631537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Drateam.B"
        threat_id = "2147631537"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Drateam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "./DRAT/" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\{7890g421-b1gf-14d0-89bb-0090ce808e85}" ascii //weight: 1
        $x_1_3 = "StartDll" ascii //weight: 1
        $x_1_4 = "MS-DOS Carry out and Fail!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Drateam_B_2147640472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Drateam.gen!B"
        threat_id = "2147640472"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Drateam"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff ff ff ff 12 00 00 00 4d 53 47 7c b8 c3 c4 bf c2 bc b2 bb b4 e6 d4 da a3 a1 00}  //weight: 1, accuracy: High
        $x_1_2 = {ff ff ff ff 14 00 00 00 4d 53 47 7c c7 fd b6 af c6 f7 ce de b7 a8 b7 c3 ce ca a3 a1 00}  //weight: 1, accuracy: High
        $x_1_3 = {ff ff ff ff 0f 00 00 00 77 71 32 6c 79 66 2e 67 69 63 70 2e 6e 65 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {43 4f 4e 4e 45 43 54 45 44 3f 0a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

