rule Trojan_Win32_Relnicar_A_2147723825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Relnicar.A!dha"
        threat_id = "2147723825"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Relnicar"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {53 69 64 3a 25 73 0d 0a 55 73 65 72 3a 25 73 0d 0a 43 6f 6d 70 75 74 65 72 3a 25 73}  //weight: 10, accuracy: High
        $x_10_2 = {4c 61 6e 20 69 70 3a 25 73 0d 0a 55 72 6c 31 3a 25 73 20}  //weight: 10, accuracy: High
        $x_10_3 = "expand.exe -F:* \"%s\"" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Relnicar_A_2147723825_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Relnicar.A!dha"
        threat_id = "2147723825"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Relnicar"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\wsc.ico.TMP" wide //weight: 10
        $x_10_2 = "\\REMOVEDISK\\" wide //weight: 10
        $x_10_3 = "sessionth=%d; uidth=%d; codeth=%d; sizeth=%d; length=%d;" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Relnicar_A_2147723825_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Relnicar.A!dha"
        threat_id = "2147723825"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Relnicar"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {77 73 63 2e 64 6c 6c 00 5f 72 75 6e 40 34 00}  //weight: 10, accuracy: High
        $x_10_2 = {b9 69 00 00 00 66 89 0c 45 [0-4] 68 00 00 00 80 b9 6f 00 00 00 68 [0-4] 66 89 0c 45}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Relnicar_A_2147724349_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Relnicar.A!dha!!Relnicar.gen!A"
        threat_id = "2147724349"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Relnicar"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        info = "Relnicar: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {53 69 64 3a 25 73 0d 0a 55 73 65 72 3a 25 73 0d 0a 43 6f 6d 70 75 74 65 72 3a 25 73}  //weight: 10, accuracy: High
        $x_10_2 = {4c 61 6e 20 69 70 3a 25 73 0d 0a 55 72 6c 31 3a 25 73 20}  //weight: 10, accuracy: High
        $x_10_3 = "expand.exe -F:* \"%s\"" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Relnicar_A_2147724350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Relnicar.A!dha!!Relnicar.gen!B"
        threat_id = "2147724350"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Relnicar"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        info = "Relnicar: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {77 73 63 2e 64 6c 6c 00 5f 72 75 6e 40 34 00}  //weight: 10, accuracy: High
        $x_10_2 = {b9 69 00 00 00 66 89 0c 45 [0-4] 68 00 00 00 80 b9 6f 00 00 00 68 [0-4] 66 89 0c 45}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Relnicar_A_2147724351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Relnicar.A!dha!!Relnicar.gen!C"
        threat_id = "2147724351"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Relnicar"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        info = "Relnicar: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "C: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\wsc.ico.TMP" wide //weight: 10
        $x_10_2 = "\\REMOVEDISK\\" wide //weight: 10
        $x_10_3 = "sessionth=%d; uidth=%d; codeth=%d; sizeth=%d; length=%d;" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

