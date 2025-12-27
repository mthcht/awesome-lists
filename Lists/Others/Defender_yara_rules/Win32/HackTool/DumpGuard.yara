rule HackTool_Win32_DumpGuard_A_2147956013_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/DumpGuard.A!MTB"
        threat_id = "2147956013"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpGuard"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DumpCredentialsRemoteCredentialGuardAll" ascii //weight: 1
        $x_1_2 = "LsaEnumerateLogonSessions" ascii //weight: 1
        $x_1_3 = "domain" ascii //weight: 1
        $x_1_4 = "username" ascii //weight: 1
        $x_1_5 = "password" ascii //weight: 1
        $x_1_6 = ".LinkedList" ascii //weight: 1
        $x_1_7 = ".Kerberos.Networking" ascii //weight: 1
        $x_1_8 = ".Spnego" ascii //weight: 1
        $x_1_9 = ".Tsssp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

