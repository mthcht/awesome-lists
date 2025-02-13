rule Backdoor_Win32_Bioazih_A_2147693186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bioazih.A!dha"
        threat_id = "2147693186"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bioazih"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 1c 08 80 f3 04 88 1c 08 40 3b c2 7c f2}  //weight: 1, accuracy: High
        $x_1_2 = "C:\\WINDOWS\\tasks\\conime.exe" wide //weight: 1
        $x_1_3 = "Pass:%s Hostname:%s Ip:%s Os:%s Proxy:%s Vm:%s Pro:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Bioazih_A_2147693186_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bioazih.A!dha"
        threat_id = "2147693186"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bioazih"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8a 04 31 c1 f8 04 83 e0 0f 83 f8 09}  //weight: 4, accuracy: High
        $x_4_2 = "bioazih" ascii //weight: 4
        $x_2_3 = "Pass:%s Hostname:%s Ip:%s Os:%s Proxy:%s Vm:%s" ascii //weight: 2
        $x_2_4 = "/ru/yy/htp.asp" ascii //weight: 2
        $x_1_5 = "LOOK PRO FINISH (total %d)" wide //weight: 1
        $x_1_6 = "/up_load" ascii //weight: 1
        $x_1_7 = "unistal" ascii //weight: 1
        $x_1_8 = ".asp?keyword=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Bioazih_B_2147693267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bioazih.B!dha"
        threat_id = "2147693267"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bioazih"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 00 72 00 65 00 20 00 79 00 6f 00 75 00 20 00 74 00 68 00 65 00 72 00 65 00 3f 00 20 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {65 78 69 74 0a 00}  //weight: 1, accuracy: High
        $x_1_3 = {68 fc 0f 00 00 8d 45 0c 6a 00 50 e8 ?? ?? ?? ?? 46 8d 85 ?? ?? ?? ?? 6b f6 2c 56 50 8d 45 0c 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Bioazih_B_2147693267_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bioazih.B!dha"
        threat_id = "2147693267"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bioazih"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "dssemh.dll" wide //weight: 2
        $x_2_2 = "success to kill process" wide //weight: 2
        $x_2_3 = "the file recv error" wide //weight: 2
        $x_3_4 = "success to delete fileforder" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

