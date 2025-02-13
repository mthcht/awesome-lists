rule Trojan_Win32_Uleux_A_2147689178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Uleux.A"
        threat_id = "2147689178"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Uleux"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Program Files\\AhnLab\\V3Lite30\\Uninst.exe" ascii //weight: 1
        $x_1_2 = "{4f645220-306d-11d2-995d-00c04f98bbc9}" ascii //weight: 1
        $x_1_3 = "sniffer.ddns.info" ascii //weight: 1
        $x_1_4 = "procMemberLogin" ascii //weight: 1
        $x_1_5 = "Login_Proc.asp" ascii //weight: 1
        $x_1_6 = "mb_password" ascii //weight: 1
        $x_1_7 = "S_T_A_R_T_S_N_I_F_F_E_R_!_@_@_!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

