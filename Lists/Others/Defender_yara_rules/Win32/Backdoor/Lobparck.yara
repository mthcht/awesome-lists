rule Backdoor_Win32_Lobparck_A_2147678293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lobparck.A"
        threat_id = "2147678293"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lobparck"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&VER=Cobra 1.2&MARK=" ascii //weight: 1
        $x_1_2 = "proc/index21.php HTTP/1.1" ascii //weight: 1
        $x_1_3 = "%s\\yamook.exe" ascii //weight: 1
        $x_1_4 = "lpk.dll" ascii //weight: 1
        $x_1_5 = "MemCode_LpkDllInitialize" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Win32_Lobparck_B_2147678294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lobparck.B"
        threat_id = "2147678294"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lobparck"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lpk.dll" ascii //weight: 1
        $x_1_2 = {6d 79 57 6f 72 6b 53 74 61 72 74 00 64 6f 75 62 6c 65 73 61 66 65}  //weight: 1, accuracy: High
        $x_1_3 = "CDA mgr" ascii //weight: 1
        $x_1_4 = {33 c9 33 c0 89 0d 48 53 40 00 a2 04 52 40 00 89 0d 4c 53 40 00 a2 dc 50 40 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

