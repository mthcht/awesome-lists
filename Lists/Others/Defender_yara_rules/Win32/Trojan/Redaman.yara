rule Trojan_Win32_Redaman_A_2147734374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redaman.A"
        threat_id = "2147734374"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redaman"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "pritePro_____e_ory" ascii //weight: 1
        $x_1_2 = "r_a_LibraryA" ascii //weight: 1
        $x_1_3 = {85 d2 74 2d 31 c9 2b 0e f7 d9 83 ee ?? 4e f7 d1 83 e9 ?? 01 d9 83 c1 ?? 49 89 cb 89 0f 83 c7 ?? 83 ea ?? 8d 0d ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? ff e1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redaman_A_2147734374_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redaman.A"
        threat_id = "2147734374"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redaman"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe" wide //weight: 1
        $x_1_2 = "c:\\programdata\\" wide //weight: 1
        $x_1_3 = "dllgetclassobject host" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redaman_B_2147734375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redaman.B"
        threat_id = "2147734375"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redaman"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {ff 10 50 8f 05 ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? c7 ?? 48 65 61 70 66 c7 ?? 04 43 72 [0-1] c7 ?? 06 65 61 [0-3] 50 ff 35 38 00 8d 05}  //weight: 3, accuracy: Low
        $x_1_2 = "LibraryA" ascii //weight: 1
        $x_1_3 = "pritePro_____e_ory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

