rule Backdoor_Win32_Spindest_B_2147686049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Spindest.B"
        threat_id = "2147686049"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Spindest"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 1c 08 80 f3 41 88 1c 08 40 3b c2 7c f2}  //weight: 1, accuracy: High
        $x_1_2 = {8d 45 01 51 c7 44 24 ?? 4d 53 55 00 89 5c 24 ?? 52 c7 06 12 00 00 00 89 46 04}  //weight: 1, accuracy: Low
        $x_1_3 = {2f 25 6c 64 6e 2e 74 78 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Spindest_C_2147688833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Spindest.C"
        threat_id = "2147688833"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Spindest"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 08 32 ca 02 ca 88 08 40 4e 75 f4}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 d8 5c c6 45 d9 63 c6 45 da 6d c6 45 db 64 c6 45 dc 2e c6 45 de 78 c6 45 e0 00}  //weight: 1, accuracy: High
        $x_1_3 = "%s SP%d (Build %d)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

