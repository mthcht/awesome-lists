rule VirTool_WinNT_Koobface_D_2147724160_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Koobface.gen!D"
        threat_id = "2147724160"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {78 3a 5c 77 6f 72 6b 5c 73 6f 66 74 76 32 5c 64 6e 73 62 6c 6f 63 6b 65 72 5c 64 72 69 76 65 72 5c 6f 62 6a [0-8] 5f 78 38 36 5c 69 33 38 36 5c 46 49 4f 33 32 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_2 = {54 64 69 4d 61 70 55 73 65 72 52 65 71 75 65 73 74 00 54 44 49 2e 53 59 53}  //weight: 1, accuracy: High
        $x_1_3 = "\\Device\\Ctrl" wide //weight: 1
        $x_1_4 = "\\Device\\UdpFilter" wide //weight: 1
        $x_1_5 = "\\Device\\TcpFilter" wide //weight: 1
        $x_1_6 = {00 49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 46 00 49 00 4f 00 33 00 32 00 2e 00 73 00 79 00 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Koobface_E_2147724161_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Koobface.gen!E"
        threat_id = "2147724161"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "oko6.sys" ascii //weight: 1
        $x_1_2 = "o6ko.sys" ascii //weight: 1
        $x_1_3 = "imapioko.sys" ascii //weight: 1
        $x_1_4 = "mrxoko.sys" ascii //weight: 1
        $x_1_5 = "vgaoko.sys" ascii //weight: 1
        $x_1_6 = "ndisoko.sys" ascii //weight: 1
        $x_1_7 = "okomoh.sys" ascii //weight: 1
        $x_1_8 = "haspsux.sys" ascii //weight: 1
        $x_1_9 = "mfoko.sys" ascii //weight: 1
        $x_1_10 = "nokomnt.sys" ascii //weight: 1
        $x_1_11 = "klifoko.sys" ascii //weight: 1
        $x_11_12 = "\\Device\\UdpFilter" wide //weight: 11
        $x_11_13 = "\\Device\\TcpFilter" wide //weight: 11
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_11_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Koobface_E_2147724161_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Koobface.gen!E"
        threat_id = "2147724161"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "\\DosDevices\\HASPNTDev" wide //weight: 5
        $x_5_2 = "\\Device\\HASPNTDev" wide //weight: 5
        $x_5_3 = "\\Device\\TcpFilter" wide //weight: 5
        $x_5_4 = "\\Device\\UdpFilter" wide //weight: 5
        $x_5_5 = {6d 61 78 69 6d 6f 2e 73 79 73 00}  //weight: 5, accuracy: High
        $x_1_6 = {ff 75 0c 83 e8 24 c6 00 0f c6 40 01 06 89 48 14 8b 4f 08 89 48 18 57 c7 40 04 02 00 00 00 89 58 08 89 58 0c 89 58 10 e8 ?? ?? 00 00 8b 4d 10 8b d6 ff 15}  //weight: 1, accuracy: Low
        $x_5_7 = {73 65 61 72 63 68 66 6f 72 3d 00}  //weight: 5, accuracy: High
        $x_5_8 = {2f 62 61 72 3f 00}  //weight: 5, accuracy: High
        $x_5_9 = {5c 5c 2e 5c 48 41 53 50 4e 54 44 65 76 00}  //weight: 5, accuracy: High
        $x_5_10 = "virus" ascii //weight: 5
        $x_5_11 = "spyware" ascii //weight: 5
        $x_1_12 = {83 7d c8 02 0f 84 ?? ?? ?? ?? 6a 03 58 6a 07 89 85 48 fd ff ff 89 85 4c fd ff ff 89 85 50 fd ff ff 89 85 54 fd ff ff 58 53 c7 85 00 fe ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_5_*) and 1 of ($x_1_*))) or
            ((5 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Koobface_C_2147724162_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Koobface.gen!C"
        threat_id = "2147724162"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IoAttachDeviceToDeviceStack" ascii //weight: 1
        $x_1_2 = "KfReleaseSpinLock" ascii //weight: 1
        $x_1_3 = "IofCompleteRequest" ascii //weight: 1
        $x_1_4 = "\\Device\\Tcp" wide //weight: 1
        $x_1_5 = "\\Device\\PodmenaFD" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Koobface_A_2147724164_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Koobface.gen!A"
        threat_id = "2147724164"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hanfc" ascii //weight: 1
        $x_1_2 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 4e 00 46 00 52 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {2d 90 01 22 00 74 58 83 e8 04 74 46 83 e8 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Koobface_B_2147724165_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Koobface.gen!B"
        threat_id = "2147724165"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hanfc" ascii //weight: 1
        $x_1_2 = "hanfr" ascii //weight: 1
        $x_2_3 = {81 fb 7f 00 00 01 74 2c 85 db 74 28 39 59 24 74 23}  //weight: 2, accuracy: High
        $x_1_4 = {81 e9 9c 01 22 00 74 12 83 e9 08 75 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Koobface_F_2147724166_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Koobface.gen!F"
        threat_id = "2147724166"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {2d 87 00 00 00 74 0f 48 48 74 0b 48 48 74 07 2d 32 01 00 00 75 07 8b c3 83 e0 fd}  //weight: 10, accuracy: High
        $x_1_2 = "\\WZS.pdb" ascii //weight: 1
        $x_1_3 = ":\\dnsblocker\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

