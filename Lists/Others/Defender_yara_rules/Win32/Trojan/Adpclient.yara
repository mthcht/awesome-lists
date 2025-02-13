rule Trojan_Win32_Adpclient_2147608709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adpclient"
        threat_id = "2147608709"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adpclient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "My_M_i_niT_C_PC_lient" ascii //weight: 1
        $x_1_2 = "ERROR:gfs   WAIT" ascii //weight: 1
        $x_1_3 = "un_A_D_C_lie_nt" ascii //weight: 1
        $x_1_4 = "vdf03n:false" ascii //weight: 1
        $x_1_5 = "g39948ent:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

