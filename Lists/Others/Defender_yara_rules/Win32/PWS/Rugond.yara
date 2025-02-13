rule PWS_Win32_Rugond_A_2147697710_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Rugond.A"
        threat_id = "2147697710"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugond"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dll\\agentReply.vbp" wide //weight: 1
        $x_1_2 = "CardUse.aspx?action=chongzhi&username=" wide //weight: 1
        $x_1_3 = "su.microrui.com/" wide //weight: 1
        $x_1_4 = "MicroSu.log" wide //weight: 1
        $x_1_5 = "QElementClient Window" ascii //weight: 1
        $x_1_6 = "wlzhuzhu.com/ksreg_server/uplogs.php?softcode=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

