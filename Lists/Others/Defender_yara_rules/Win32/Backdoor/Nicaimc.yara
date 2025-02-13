rule Backdoor_Win32_Nicaimc_A_2147794248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Nicaimc.A"
        threat_id = "2147794248"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Nicaimc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "ELLIOTALDERSONTYRELLWELLICK" ascii //weight: 2
        $x_1_2 = "AppContainerDbg.crt" ascii //weight: 1
        $x_1_3 = "Global\\CMIACIN" ascii //weight: 1
        $x_1_4 = {be 11 00 00 00 f7 fe 0f ?? ?? ?? ?? 33 ca 8b 45 08 03 45 fc 88 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

