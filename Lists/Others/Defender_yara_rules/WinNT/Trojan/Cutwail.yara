rule Trojan_WinNT_Cutwail_A_2147596633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Cutwail.A!sys"
        threat_id = "2147596633"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Cutwail"
        severity = "Critical"
        info = "sys: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f bf 00 3d 93 08 00 00 [0-15] 0f}  //weight: 1, accuracy: Low
        $x_2_2 = {fa 0f 20 c0 89 45 fc 25 ff ff fe ff 0f 22 c0}  //weight: 2, accuracy: High
        $x_1_3 = {8b 45 08 8b 75 0c 05 54 01 00 00 8a 10 8a ca 3a 16 75 1f}  //weight: 1, accuracy: High
        $x_1_4 = {b9 86 00 00 00 33 c0 8b fe f3 ab 68 03 01 00 00 ff 75 08 56}  //weight: 1, accuracy: High
        $x_1_5 = {33 f6 8b 45 08 6a ff 6a ff ff 74 b5 f0 ff 70 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_WinNT_Cutwail_B_2147596634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Cutwail.B!sys"
        threat_id = "2147596634"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Cutwail"
        severity = "Critical"
        info = "sys: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c6 45 ff 00 c6 45 fe 01 fa 0f 20 c0 89 45 f8 25 ff ff fe ff 0f 22 c0 33 d2 39 55 0c 76 3e 8b 45}  //weight: 2, accuracy: High
        $x_1_2 = {6a 4d 8d 85 24 ff ff ff 50 e8}  //weight: 1, accuracy: High
        $x_1_3 = {30 4d 0f 8a 4d 0f 88 0c 10 40 3b c6 72 e3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Cutwail_C_2147596636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Cutwail.C!sys"
        threat_id = "2147596636"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Cutwail"
        severity = "Critical"
        info = "sys: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Device\\m5" wide //weight: 1
        $x_1_2 = "\\Device\\main35" wide //weight: 1
        $x_1_3 = "\\DosDevices\\m5" wide //weight: 1
        $x_1_4 = "\\DosDevices\\main35" wide //weight: 1
        $x_1_5 = {63 3a 5c 30 62 75 6c 6b 6e 65 74 5c 62 75 69 6c 64 5f 72 6f 6f 74 5c 72 2d 6c 6f 61 64 65 72 2e ?? ?? 5c 72 6f 6f 74 5c 69 33 38 36 5c 6d 61 69 6e 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_6 = "main.sys" ascii //weight: 1
        $x_1_7 = "\\??\\C:\\WINDOWS\\system32\\wsys.dll" wide //weight: 1
        $x_1_8 = "\\??\\C:\\WINNT\\system32\\wsys.dll" wide //weight: 1
        $x_1_9 = "\\SystemRoot\\system32\\wsys.dll" ascii //weight: 1
        $x_1_10 = "h.dllhwsysT" ascii //weight: 1
        $x_1_11 = "IoDeleteSymbolicLink" ascii //weight: 1
        $x_1_12 = "ZwCreateFile" ascii //weight: 1
        $x_1_13 = "KeBugCheckEx" ascii //weight: 1
        $x_1_14 = "ntoskrnl.exe" ascii //weight: 1
        $x_1_15 = "ZwWriteFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

rule Trojan_WinNT_Cutwail_D_2147596637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Cutwail.D!sys"
        threat_id = "2147596637"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Cutwail"
        severity = "Critical"
        info = "sys: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb d4 5e 8b fe 8b 76 24 03 f3 66 8b 14 56 2b 57 10 42 8b 77 1c 03 f3 8b 04 96 03 c3 6a 00 68 2e 64 6c 6c 68 77 73 79 73 54 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

