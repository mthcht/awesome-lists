rule Backdoor_Win32_Nioupale_A_2147689430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Nioupale.A"
        threat_id = "2147689430"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Nioupale"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "mshost.exe" ascii //weight: 1
        $x_1_2 = {6d 73 69 64 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {cc 38 38 34 e2 f7 f7}  //weight: 1, accuracy: High
        $x_1_4 = {f7 c5 c8 c8 3a f6 cf cd ce}  //weight: 1, accuracy: High
        $x_1_5 = "/addr.gif" ascii //weight: 1
        $x_1_6 = {25 55 53 45 52 50 52 4f 46 49 4c 45 25 5c 53 79 73 74 65 6d ?? ?? ?? ?? 5c 4c 69 62 72 61 72 79 ?? ?? ?? ?? 5c 53 79 73 74 65 6d 00 43 6f 6d 6d 6f 6e 46 69 6c 65 73 44 69 72}  //weight: 1, accuracy: Low
        $x_1_7 = {74 65 78 74 3d 49 44 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

