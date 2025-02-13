rule HackTool_Win32_Mexlib_A_2147827201_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mexlib.A!dha"
        threat_id = "2147827201"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mexlib"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "?AVdb_lsa_secrets@@" ascii //weight: 1
        $x_1_2 = "?AVdb_winvault_passwd@@" ascii //weight: 1
        $x_1_3 = "?AVdb_thunderbird_passwd@@" ascii //weight: 1
        $x_1_4 = "?AVdb_wlan_passwd@@" ascii //weight: 1
        $x_1_5 = "?AVese_db@@" ascii //weight: 1
        $x_1_6 = "?AVdpapi_vault_file@@" ascii //weight: 1
        $x_1_7 = "?AVmodbuf@@" ascii //weight: 1
        $x_1_8 = "?AVbufread@@" ascii //weight: 1
        $x_1_9 = "?AVwinmutex@@" ascii //weight: 1
        $x_1_10 = "?AVrc4@@" ascii //weight: 1
        $x_1_11 = "?AVsqldb_see@@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

