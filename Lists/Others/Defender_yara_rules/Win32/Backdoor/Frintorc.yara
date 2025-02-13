rule Backdoor_Win32_Frintorc_A_2147605619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Frintorc.A!dll"
        threat_id = "2147605619"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Frintorc"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "1.3.6.1.5.5.7.3.2" ascii //weight: 1
        $x_1_2 = "%s:%d/aspxabcdefg.asp?" ascii //weight: 1
        $x_1_3 = "User-Agent: webclient" ascii //weight: 1
        $x_1_4 = "IMJPMIG" ascii //weight: 1
        $x_1_5 = "\\user.ini" ascii //weight: 1
        $x_2_6 = "tigerwood.vicp.net" ascii //weight: 2
        $x_2_7 = "otna.vicp.net" ascii //weight: 2
        $x_2_8 = "zipdg.dll" wide //weight: 2
        $x_2_9 = "secur32.dll" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((4 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

