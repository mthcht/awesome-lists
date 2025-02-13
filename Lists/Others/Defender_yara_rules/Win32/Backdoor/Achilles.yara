rule Backdoor_Win32_Achilles_A_2147696093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Achilles.A!dha"
        threat_id = "2147696093"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Achilles"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1000"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "login by user and pwd failed" wide //weight: 1
        $x_1_2 = "get the target process but can't open it:%d" wide //weight: 1
        $x_1_3 = ":shellcode" wide //weight: 1
        $x_1_4 = "Achilles" ascii //weight: 1
        $x_1_5 = "Global\\kill_%0.8d_adsf" ascii //weight: 1
        $x_1_6 = "GET \\DOOM HTTP1/1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

