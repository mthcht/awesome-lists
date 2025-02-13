rule Backdoor_Win32_Htbot_A_2147678671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Htbot.A"
        threat_id = "2147678671"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Htbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {69 c0 fd 43 03 00 05 c9 9e 26 00 33 d2 b9 30 75 00 00}  //weight: 2, accuracy: High
        $x_1_2 = "@firewall add allowedprogram \"%s\" \"%s\" ENABLE" wide //weight: 1
        $x_1_3 = {3f 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 3d 00 75 00 70 00 64 00 61 00 74 00 65 00 90 00 02 00 01 00 26 00 69 00 64 00 3d 00 25 00 73 00 26 00 69 00 70 00 3d 00 25 00 73 00 26 00 70 00 6f 00 72 00 74 00 3d 00 25 00 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Htbot_B_2147678895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Htbot.B"
        threat_id = "2147678895"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Htbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 04 8d 4c 24 ?? 51 52 c7 44 24 ?? 01 00 cc ee ff 15 ?? ?? ?? ?? 83 f8 04}  //weight: 1, accuracy: Low
        $x_1_2 = "?command=getbackconnect" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Htbot_C_2147707966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Htbot.C"
        threat_id = "2147707966"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Htbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "?command=getbackconnect" wide //weight: 1
        $x_1_2 = "\\Mnto2" wide //weight: 1
        $x_1_3 = "firewall add allowedprogram \"%s\" \"%s\" ENABLE" wide //weight: 1
        $x_1_4 = "%s?command=update&id=%s&ip=%s&port=%d" wide //weight: 1
        $x_1_5 = "%s?command=ghl&id=%s" wide //weight: 1
        $x_1_6 = "\\farclen.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

