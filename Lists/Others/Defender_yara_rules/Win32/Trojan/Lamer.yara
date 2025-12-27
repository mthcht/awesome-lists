rule Trojan_Win32_Lamer_A_2147710006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lamer.A!bit"
        threat_id = "2147710006"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lamer"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\FEDOT\\Fedot.exe" ascii //weight: 1
        $x_1_2 = "C:\\Service\\dat." ascii //weight: 1
        $x_1_3 = "XX.CPP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lamer_RPZ_2147889424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lamer.RPZ!MTB"
        threat_id = "2147889424"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lamer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b9 40 00 00 00 33 c0 8d 7c 24 0d c6 44 24 0c 00 f3 ab 66 ab aa 8b fd 83 c9 ff 33 c0 8d 54 24 0c f2 ae f7 d1 2b f9 8b f7 8b fa 8b d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lamer_KGAA_2147907480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lamer.KGAA!MTB"
        threat_id = "2147907480"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lamer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {e8 ab b1 ff ff 34 ef 34 ef 34 ef 34 ef 34 ef 34 ef 34 ef 34 ef 34 ef 34 ef 34 ef 34 ef 34 ef 34 ef 34 ef 34 ef 34 ef 34 ef 34 ef 34 ef 34 ef 34}  //weight: 4, accuracy: High
        $x_4_2 = {e8 ab b1 ff ff 87 c9 87 c9 87 c9 87 c9 87 c9 87 c9 87 c9 87 c9 87 c9 87 c9 87 c9 87 c9 87 c9 87 c9 87 c9 87 c9 87 c9 87 c9 87 c9 87 c9 87 c9 87}  //weight: 4, accuracy: High
        $x_4_3 = {e8 ab b1 ff ff 80 c4 ef 80 ec ef 80 c4 ef 80 ec ef 80 c4 ef 80 ec ef 80 c4 ef 80 ec ef 80 c4 ef 80 ec ef 80 c4 ef 80 ec ef 80 c4 ef 80 ec ef 80}  //weight: 4, accuracy: High
        $x_4_4 = {e8 ab b1 ff ff 66 81 f3 89 00 66 81 f3 89 00 66 81 f3 89 00 66 81 f3 89 00 66 81 f3 89 00 66 81 f3 89 00 66 81 f3 89 00 66 81 f3 89 00 66 81 f3}  //weight: 4, accuracy: High
        $x_4_5 = {e8 ab b1 ff ff 89 c0 89 c0 89 c0 86 d2 86 d2 86 d2 86 d2 86 d2 86 d2 86 d2 86 d2 86 d2 86 d2 86 d2 86 d2 86 d2 86 d2 86 d2 86 d2 86 d2 86 d2 86}  //weight: 4, accuracy: High
        $x_1_6 = {2f 68 6f 6d 65 2f 7a 61 74 6f 2f 65 78 70 2f 00 76 69 73 75 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Lamer_C_2147945428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lamer.C!MTB"
        threat_id = "2147945428"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lamer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "VirtualAllocEx\",\"SUCCESS\",\"0x00990000\",\"th32ProcessID->1824\",\"szExeFile->HelpMe.exe\",\"lpAddress->0x00000000\",\"dwSize->4096\",\"flAllocationType->0x00001000\",\"flProtect->0x00000040" ascii //weight: 2
        $x_1_2 = "shellexecute=AutoRun.exe" ascii //weight: 1
        $x_1_3 = "Internet Explorer.lnk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

