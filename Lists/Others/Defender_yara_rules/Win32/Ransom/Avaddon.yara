rule Ransom_Win32_Avaddon_PA_2147756676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Avaddon.PA!MTB"
        threat_id = "2147756676"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Avaddon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your network has been infected by <span>Avaddon" ascii //weight: 1
        $x_1_2 = "have been <b>encrypted" ascii //weight: 1
        $x_1_3 = "Avaddon General Decryptor" ascii //weight: 1
        $x_1_4 = "1\\BIN\\%s.exe" ascii //weight: 1
        $x_1_5 = "\\XMedCon\\bin\\medcon.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Avaddon_AA_2147757739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Avaddon.AA!MTB"
        threat_id = "2147757739"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Avaddon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your network has been infected by <span>Avaddon" ascii //weight: 1
        $x_1_2 = "have been <b>encrypted" ascii //weight: 1
        $x_1_3 = "Avaddon General Decryptor" ascii //weight: 1
        $x_1_4 = "1\\BIN\\gm.exe" ascii //weight: 1
        $x_1_5 = "\\XMedCon\\bin\\medcon.exe" ascii //weight: 1
        $x_1_6 = "<p>Do not try to recover files yourself!</p>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_Win32_Avaddon_PB_2147758685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Avaddon.PB!MTB"
        threat_id = "2147758685"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Avaddon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e0 02 89 [0-5] 8b [0-5] 83 e9 04 89 [0-5] c7 [0-5] 04 00 00 00 8b [0-5] c1 e2 02 89 [0-5] 8b [0-5] 83 e8 04 89 [0-5] c7 [0-5] 04 00 00 00 8b [0-5] c1 e1 02 89 [0-5] 8b [0-5] 83 ea 04 89 [0-5] c7 [0-5] 04 00 00 00 8b [0-5] c1 e0 02 89 [0-5] 8b [0-5] 83 e9 04}  //weight: 1, accuracy: Low
        $x_2_2 = {b9 01 00 00 00 85 c9 0f 70 00 8d [0-5] 00 00 2b [0-5] 03 [0-5] a3 [0-5] 8b [0-5] 81 e9 2d ad 00 00 89 [0-5] 8b [0-5] 03 [0-5] 03 [0-5] 89 [0-5] a1 [0-5] 2b [0-5] a3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Avaddon_KP_2147758825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Avaddon.KP"
        threat_id = "2147758825"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Avaddon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your network has been infected by <span>Avaddon" ascii //weight: 1
        $x_1_2 = "have been <b>encrypted" ascii //weight: 1
        $x_1_3 = "Avaddon General Decryptor" ascii //weight: 1
        $x_1_4 = "\\XMedCon\\bin\\medcon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Avaddon_C_2147759060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Avaddon.C!MTB"
        threat_id = "2147759060"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Avaddon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your network has been infected" ascii //weight: 1
        $x_1_2 = ".onion" ascii //weight: 1
        $x_1_3 = "Tor browser" ascii //weight: 1
        $x_1_4 = "Do not try to recover" ascii //weight: 1
        $x_1_5 = "files forever" ascii //weight: 1
        $x_2_6 = "<title>Avaddon</title>" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Avaddon_MK_2147759332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Avaddon.MK!MTB"
        threat_id = "2147759332"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Avaddon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 06 8d 4d bc 34 ?? 04 ?? 34 ?? 0f b6 c0 50 e8 ?? ?? ?? ?? 46 3b f7 75 e7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Avaddon_SS_2147759854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Avaddon.SS!MTB"
        threat_id = "2147759854"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Avaddon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ycvI0MvaztfSzdbEseGhp7I=" ascii //weight: 1
        $x_1_2 = "xsTWy8nLyNfSzdY=" ascii //weight: 1
        $x_1_3 = "wPLv9ejg5A==" ascii //weight: 1
        $x_1_4 = "vcbk9uvkvdrt7bnG5Pbr5A==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Avaddon_P_2147783567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Avaddon.P!MSR"
        threat_id = "2147783567"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Avaddon"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "your files have been encrypted" ascii //weight: 2
        $x_1_2 = ".onion" ascii //weight: 1
        $x_1_3 = "Tor browser" ascii //weight: 1
        $x_2_4 = "read_me_lock.txt" ascii //weight: 2
        $x_1_5 = "C:\\Users\\lock.txt" wide //weight: 1
        $x_1_6 = "Win32_ShadowCopy.ID='%s'" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

