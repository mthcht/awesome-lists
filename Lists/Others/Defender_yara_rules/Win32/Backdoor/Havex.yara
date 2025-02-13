rule Backdoor_Win32_Havex_A_2147687981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Havex.A!dha"
        threat_id = "2147687981"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Havex"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Programm was started at %02i:%02i:%02i" wide //weight: 1
        $x_1_2 = "Start finging of LAN hosts" wide //weight: 1
        $x_1_3 = "Start finging of OPC Servers" wide //weight: 1
        $x_1_4 = "OPC Servers not found. Programm finished" wide //weight: 1
        $x_1_5 = "OPC Server[%s\\%s] v%i.%i(b%i)" wide //weight: 1
        $x_1_6 = "OPCServer%02i.txt" wide //weight: 1
        $x_1_7 = "MTMxMjMxMg==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Win32_Havex_B_2147687982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Havex.B!dha"
        threat_id = "2147687982"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Havex"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MTMxMjMxMg==" wide //weight: 1
        $x_1_2 = "fertger" wide //weight: 1
        $x_1_3 = "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/1.0.154.36 Safari/525.19" wide //weight: 1
        $x_1_4 = {5c 00 5c 00 2e 00 5c 00 70 00 69 00 70 00 65 00 5c 00 6d 00 79 00 70 00 [0-2] 70 00 65 00 2d 00}  //weight: 1, accuracy: Low
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_6 = {5c 00 71 00 6c 00 6e 00 2e 00 64 00 62 00 78 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Win32_Havex_E_2147705726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Havex.E!dha"
        threat_id = "2147705726"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Havex"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 58 3c 03 d8 83 c3 78 8b 1b 03 d8 33 d2 8b 4b 20 03 c8 56 52}  //weight: 1, accuracy: High
        $x_1_2 = {00 00 74 00 68 00 65 00 62 00 61 00 74 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 00 73 00 6b 00 79 00 70 00 65 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 00 64 00 64 00 65 00 78 00 2e 00 65 00 78 00 65 00 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

