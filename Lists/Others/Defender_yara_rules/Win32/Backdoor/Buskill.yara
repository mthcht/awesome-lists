rule Backdoor_Win32_Buskill_A_2147721443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Buskill.A!bit"
        threat_id = "2147721443"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Buskill"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Our destiny depends only on us" ascii //weight: 1
        $x_1_2 = "if not happen so" ascii //weight: 1
        $x_1_3 = "do you know John Rembo" ascii //weight: 1
        $x_1_4 = "it is reputation" ascii //weight: 1
        $x_1_5 = "Never forget your friends" ascii //weight: 1
        $x_1_6 = "it changes every day" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

