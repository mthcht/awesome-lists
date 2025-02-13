rule Backdoor_Win32_VBbot_T_2147574837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/VBbot.T"
        threat_id = "2147574837"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "VBbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "e>0|lphp|v1xfrs1Xd877Gw;86}umufe/idx" wide //weight: 10
        $x_10_2 = "e>0|lphp|v1xfrs1Xd877Gw;86}umuf2efy" wide //weight: 10
        $x_10_3 = "%hvilegvq#ietyu|" wide //weight: 10
        $x_10_4 = ": castrionul " wide //weight: 10
        $x_10_5 = "ombrl0jm3xu2vsggvojw0ssl" wide //weight: 10
        $x_2_6 = "Regregistrii" ascii //weight: 2
        $x_2_7 = "oleadx" ascii //weight: 2
        $x_2_8 = "ollead" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_2_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

