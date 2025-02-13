rule VirTool_Win32_SuspSchTaskCmd_A_2147852907_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspSchTaskCmd.A!MTB"
        threat_id = "2147852907"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspSchTaskCmd"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 51 00 20 00 2f 00 63 00 20 00 63 00 64 00 20 00 2f 00 64 00 20 00 43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 20 00 26 00 20 00 65 00 63 00 68 00 6f 00 20 00 [0-32] 20 00 3e 00 20 00}  //weight: 2, accuracy: Low
        $x_2_2 = {20 00 32 00 3e 00 26 00 31 00 20 00 26 00 20 00 65 00 63 00 68 00 6f 00 20 00 [0-32] 20 00 3e 00 3e 00}  //weight: 2, accuracy: Low
        $x_1_3 = " & cd >>" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

