rule Trojan_Win32_Depriz_B_2147718364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Depriz.B!dha"
        threat_id = "2147718364"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Depriz"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {2b c2 d1 f8 56 57 8b f8 33 c9 8d 5f 01 8b c3 ba 02 00 00 00 f7 e2 0f 90 c1 f7 d9 0b c8 51 e8 ?? ?? ?? ?? 8b f0 8b 45 08 53 50 56 e8 ?? ?? ?? ?? 83 c4 10 33 c0 85 ff}  //weight: 3, accuracy: Low
        $x_1_2 = "cmd.exe /c \"ping -n 30 127.0.0.1 >nul && sc config %s binpath= \"%s LocalService\" && ping -n 10 127.0.0.1 >nul && sc start %s \"" wide //weight: 1
        $x_1_3 = "LanmanWorkstation" wide //weight: 1
        $x_1_4 = {72 00 64 00 73 00 61 00 64 00 6d 00 69 00 6e 00 00 00 72 00 65 00 67 00 73 00 79 00 73 00 00 00 73 00 69 00 67 00 76 00 65 00 72 00 00 00 72 00 6f 00 75 00 74 00 65 00 6d 00 61 00 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Depriz_C_2147718403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Depriz.C!dha"
        threat_id = "2147718403"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Depriz"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 ff 00 94 35 77 73 ?? ff c7 48 83 c0 02 eb e5}  //weight: 1, accuracy: Low
        $x_1_2 = "drdisk.sys" wide //weight: 1
        $x_1_3 = "ntssrvr32.exe" wide //weight: 1
        $x_1_4 = "ntssrvr64.exe" wide //weight: 1
        $x_1_5 = "\\inf\\usbvideo324.pnf" wide //weight: 1
        $x_1_6 = "\\inf\\netimm173.pnf" wide //weight: 1
        $x_1_7 = "Wow64DisableWow64FsRedirection" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_Depriz_E_2147718876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Depriz.E!dha"
        threat_id = "2147718876"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Depriz"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ">nul && sc config %s binpath= \"%s LocalService\" && ping -n" wide //weight: 1
        $x_1_2 = {5c 00 69 00 6e 00 66 00 5c 00 [0-16] 2e 00 70 00 6e 00 66 00}  //weight: 1, accuracy: Low
        $x_1_3 = "LanmanWorkstation" wide //weight: 1
        $x_1_4 = "ntertmgr32.exe" wide //weight: 1
        $x_1_5 = "ntertmgr64.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Depriz_F_2147719573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Depriz.F!dha"
        threat_id = "2147719573"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Depriz"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "shutdown -r -f -t 2" ascii //weight: 1
        $x_1_2 = {5c 00 69 00 6e 00 66 00 5c 00 [0-16] 2e 00 70 00 6e 00 66 00}  //weight: 1, accuracy: Low
        $x_1_3 = "type= kernel start= demand binpath= System32\\Drivers\\" ascii //weight: 1
        $x_1_4 = "ntertmgr32.exe" wide //weight: 1
        $x_1_5 = "ntertmgr64.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

