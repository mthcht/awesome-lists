rule Backdoor_Win32_Chadivendo_STF_2147779251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Chadivendo.STF"
        threat_id = "2147779251"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Chadivendo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 7c 3e fe 52 75 ?? 80 7c 3e fd 49 75 ?? 80 7c 3e fc 44 75 ?? 80 7c 3e fb 3c}  //weight: 1, accuracy: Low
        $x_1_2 = {ba 01 01 00 00 66 3b c2 74 ?? ba 01 02 00 00 66 3b c2 74 ?? ba 01 04 00 00 66 3b c2 74 ?? ba 01 08 00 00 66 3b c2}  //weight: 1, accuracy: Low
        $x_1_3 = {68 74 74 70 3a 2f 2f 25 73 [0-32] 25 30 38 78 2e 74 78 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

