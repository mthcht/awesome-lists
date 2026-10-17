rule Trojan_Win32_RevShell_PS_2147833351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RevShell.PS!MTB"
        threat_id = "2147833351"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RevShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 8d c0 e5 ff ff ba ab 3c 00 00 66 89 95 f8 f7 ff ff b8 ?? ?? ?? ?? 66 89 85 fa f7 ff ff b9 ?? ?? ?? ?? 66 89 8d fc f7 ff ff 33 d2 66 89 95 fe f7 ff ff b8 ?? ?? ?? ?? 66 89 85 84 f4 ff ff b9 ?? ?? ?? ?? 66 89 8d 86 f4 ff ff ba ?? ?? ?? ?? 66 89 95 88 f4 ff ff 33 c0 66 89 85 8a f4 ff ff b9}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 01 00 00 00 c1 e1 02 0f b6 54 0d ac 03 c2 b9 01 00 00 00 c1 e1 02 88 44 0d d4 ba 02 00 00 00 d1 e2}  //weight: 1, accuracy: High
        $x_1_3 = "ReverseShell.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RevShell_MUA_2147979871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RevShell.MUA!MTB"
        threat_id = "2147979871"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RevShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "(get-date).addseconds(" wide //weight: 10
        $x_10_2 = ".connectasync(" wide //weight: 10
        $x_10_3 = {6e 00 65 00 74 00 2e 00 73 00 6f 00 63 00 6b 00 65 00 74 00 73 00 2e 00 74 00 63 00 70 00 63 00 6c 00 69 00 65 00 6e 00 74 00 [0-255] 2e 00 67 00 65 00 74 00 73 00 74 00 72 00 65 00 61 00 6d 00 28 00 29 00}  //weight: 10, accuracy: Low
        $x_10_4 = ".streamwriter(" wide //weight: 10
        $x_1_5 = "invoke-expression" wide //weight: 1
        $x_1_6 = "iex" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_RevShell_MUB_2147979872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RevShell.MUB!MTB"
        threat_id = "2147979872"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RevShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "[environment]::username" wide //weight: 1
        $x_1_2 = "=$([environment]::machinename)" wide //weight: 1
        $x_1_3 = {2e 00 47 00 65 00 74 00 42 00 79 00 74 00 65 00 73 00 [0-9] 43 00 41 00 4c 00 4c 00 42 00 41 00 43 00 4b 00}  //weight: 1, accuracy: Low
        $x_1_4 = {6e 00 65 00 74 00 2e 00 73 00 6f 00 63 00 6b 00 65 00 74 00 73 00 2e 00 74 00 63 00 70 00 63 00 6c 00 69 00 65 00 6e 00 74 00 [0-255] 2e 00 67 00 65 00 74 00 73 00 74 00 72 00 65 00 61 00 6d 00 28 00 29 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RevShell_MUC_2147980505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RevShell.MUC!MTB"
        threat_id = "2147980505"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RevShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "array_filter(" wide //weight: 1
        $x_1_2 = "rawurldecode(" wide //weight: 1
        $x_1_3 = "is_writable(" wide //weight: 1
        $x_1_4 = "file_put_contents(" wide //weight: 1
        $x_1_5 = "include" wide //weight: 1
        $x_1_6 = "finally" wide //weight: 1
        $x_1_7 = "@unlink(" wide //weight: 1
        $x_1_8 = "die(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

