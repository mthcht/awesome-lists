rule HackTool_Win32_Passdash_A_2147694166_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Passdash.A!dha"
        threat_id = "2147694166"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Passdash"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b cd 2b 4f 34 8d 86 a0 00 00 00 51 55 e8 ?? ?? ?? ?? 8d 7e 28 8d 54 24 ?? 8b cb c7 44 24 ?? 00 00 00 00 e8}  //weight: 2, accuracy: Low
        $x_2_2 = "Changing NTLM credentials of logon session" ascii //weight: 2
        $x_1_3 = "LUID:UserName:LogonDomain:LMhash:NThash" ascii //weight: 1
        $x_1_4 = {2d 64 62 67 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

