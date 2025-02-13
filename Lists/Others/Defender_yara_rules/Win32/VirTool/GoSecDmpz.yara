rule VirTool_Win32_GoSecDmpz_A_2147890119_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/GoSecDmpz.A!MTB"
        threat_id = "2147890119"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "GoSecDmpz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ditreader.DumpedHash.HashString" ascii //weight: 1
        $x_1_2 = "ditreader.SAMRRPCSID.Rid" ascii //weight: 1
        $x_1_3 = "ditreader.NewSAMRKerbStoredCredNew" ascii //weight: 1
        $x_1_4 = "ditreader.DitReader.Dump" ascii //weight: 1
        $x_1_5 = "samreader.SAMHashAESInfo" ascii //weight: 1
        $x_1_6 = "samreader.User_Account_V" ascii //weight: 1
        $x_1_7 = "samreader.Domain_Account_F" ascii //weight: 1
        $x_1_8 = "ntdsFileLocation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

