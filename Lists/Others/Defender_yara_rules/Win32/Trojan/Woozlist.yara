rule Trojan_Win32_Woozlist_A_2147694147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Woozlist.A"
        threat_id = "2147694147"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Woozlist"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ProcessMointer.pdb" ascii //weight: 1
        $x_1_2 = "\\mointerx64\\objfre" ascii //weight: 1
        $x_1_3 = "\\Device\\Tcp" wide //weight: 1
        $x_1_4 = {54 72 61 6e 73 70 6f 72 74 41 64 64 72 65 73 73 [0-32] 43 6f 6e 6e 65 63 74 69 6f 6e 43 6f 6e 74 65 78 74}  //weight: 1, accuracy: Low
        $x_1_5 = "\\Registry\\Machine\\System\\ControlSet001\\Services\\ProcessMoint" wide //weight: 1
        $x_1_6 = "101.226.4.6" ascii //weight: 1
        $x_1_7 = "#20481!" ascii //weight: 1
        $x_1_8 = "h.bbyyjy.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_Woozlist_B_2147705499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Woozlist.B"
        threat_id = "2147705499"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Woozlist"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6b 72 6e 6c 6e [0-5] 64 30 39 66 32 33 34 30 38 31 38 35 31 31 64 33 39 36 66 36 61 61 66 38 34 34 63 37 65 33 32 35}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 69 6e 69 [0-32] 34 45 44 36 31 39 42 39 46 43 44 41 35 34 38 38 43 31 42 34 39 46 36 39 43 44 39 30 34 39 43 31 38 43 31 30 38 43 42 41 45 31}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 6a 70 67 [0-32] 5c 50 72 6f 67 72 61 6d 5c 6a 69 72 75 2e 74 78 74}  //weight: 1, accuracy: Low
        $x_1_4 = "\\DosDevices\\LTian" wide //weight: 1
        $x_1_5 = "F7FC1AE45C5C4758AF03EF19F18A395D" ascii //weight: 1
        $x_1_6 = "AF6AD80AA4244A59AFB3D83ECF5173CC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

