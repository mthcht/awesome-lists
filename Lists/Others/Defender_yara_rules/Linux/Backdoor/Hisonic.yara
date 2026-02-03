rule Backdoor_Linux_Hisonic_A_2147962242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Hisonic.A!MSR"
        threat_id = "2147962242"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Hisonic"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.(*Service).HttpCmd" ascii //weight: 1
        $x_1_2 = "main.(*Service).HttpPing" ascii //weight: 1
        $x_1_3 = "CmdSRunCode" ascii //weight: 1
        $x_1_4 = "CmdCRunCmdResult" ascii //weight: 1
        $x_1_5 = "CmdSSwitchTCP" ascii //weight: 1
        $x_1_6 = "(*SRunCmd).GetArgs" ascii //weight: 1
        $x_1_7 = "(*CmdCPingCid).ReadBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

