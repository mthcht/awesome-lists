rule Backdoor_Win32_Midie_A_2147762577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Midie.A!MTB"
        threat_id = "2147762577"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 1e 31 d3 89 1f 83 c6 04 83 c7 04 83 e9 01 89 c8 85 c1 75 eb}  //weight: 10, accuracy: High
        $x_1_2 = "GetFirmwareEnvironmentVariableW" ascii //weight: 1
        $x_1_3 = "SCardEstablishContext" ascii //weight: 1
        $x_10_4 = {50 5f b9 08 00 00 00 f3 a6 75 ef}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

