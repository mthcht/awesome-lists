rule Trojan_Win32_Ardsw_F_2147727709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ardsw.F"
        threat_id = "2147727709"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ardsw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "minkernel\\crts\\ucrt\\inc\\corecrt_internal_strtox.h" wide //weight: 1
        $x_1_2 = {2f 63 20 73 74 61 72 74 20 22 22 20 22 25 73 22 20 25 73 00}  //weight: 1, accuracy: High
        $x_1_3 = "Aacker.com/interfhttp://www.opttr" ascii //weight: 1
        $x_1_4 = "hCppWindowsService in OnStart" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ardsw_A_2147728171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ardsw.A"
        threat_id = "2147728171"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ardsw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CurrentVersion\\Run /v %s /f" wide //weight: 1
        $x_1_2 = "taskkill /pid %d /f && del /f/s/q \"%s\"" wide //weight: 1
        $x_1_3 = "ipconfig /flushdns" wide //weight: 1
        $x_1_4 = "\\pxry.dat" ascii //weight: 1
        $x_1_5 = "Error:You have in a shell,please exit it first!" wide //weight: 1
        $x_1_6 = "Error:No user is logoned!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

