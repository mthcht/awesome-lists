rule Backdoor_Win32_Mozaakai_A_2147767088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mozaakai.A!MTB"
        threat_id = "2147767088"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mozaakai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "workrepair.bazar" ascii //weight: 1
        $x_1_2 = "realfish.bazar" ascii //weight: 1
        $x_1_3 = "eventmoult.bazar" ascii //weight: 1
        $x_1_4 = "younika-hayde.bazar" ascii //weight: 1
        $x_5_5 = "Sleep %u msecs" ascii //weight: 5
        $x_5_6 = "Run PowerShell script without a file" ascii //weight: 5
        $x_5_7 = "os[1]=&os[2]=&os[3]=" ascii //weight: 5
        $x_5_8 = "Getting antiviruses versions" ascii //weight: 5
        $x_5_9 = "net localgroup \"administrator" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_5_*) and 2 of ($x_1_*))) or
            ((5 of ($x_5_*))) or
            (all of ($x*))
        )
}

