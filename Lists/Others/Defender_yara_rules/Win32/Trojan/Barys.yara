rule Trojan_Win32_Barys_GMF_2147888464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Barys.GMF!MTB"
        threat_id = "2147888464"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b 1f 00 00 18 0b 30 ?? aa 5c d7 07 b5 03}  //weight: 10, accuracy: Low
        $x_10_2 = {09 f3 00 51 3c 30 16 09 50 bd 44 26 0c fc}  //weight: 10, accuracy: High
        $x_1_3 = "haryAhLibrhLoadTU" ascii //weight: 1
        $x_1_4 = "hThrehExitTU" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Barys_AMAA_2147892662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Barys.AMAA!MTB"
        threat_id = "2147892662"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 48 1e 30 4c 05 d0 48 ff c0 48 83 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Barys_GMA_2147896750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Barys.GMA!MTB"
        threat_id = "2147896750"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EL2R8RPv5LmwFPP" ascii //weight: 1
        $x_1_2 = "amaN4nuxvAwpOX" ascii //weight: 1
        $x_1_3 = "vAKA3qwQkHOpEXv8" ascii //weight: 1
        $x_1_4 = "ce8jHHJEVsGmRyNjfECj4nL" ascii //weight: 1
        $x_1_5 = "n01YP87cyoG79M" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Barys_PACS_2147899723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Barys.PACS!MTB"
        threat_id = "2147899723"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 55 08 8b 45 f8 01 d0 0f b6 08 8b 45 f8 83 e0 1f 0f b6 54 05 d8 8b 5d 08 8b 45 f8 01 d8 31 ca 88 10 83 45 f8 01 8b 45 f8 3b 45 0c 72 d2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Barys_RB_2147900504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Barys.RB!MTB"
        threat_id = "2147900504"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 54 24 20 03 54 24 08 8a 6d 00 8a 22 30 e5 88 6d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Barys_RC_2147900505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Barys.RC!MTB"
        threat_id = "2147900505"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 6d 00 8a 0e 31 f6 30 cd 88 6d 00 8b 5c 24 04 83 c3 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Barys_GXV_2147903534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Barys.GXV!MTB"
        threat_id = "2147903534"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 16 07 1c f3 67 54 35 ?? ?? ?? ?? 45 56 f6 2f 2f 16 f6 62 38 6c}  //weight: 5, accuracy: Low
        $x_5_2 = {f6 3f 04 d4 20 37 8b 52 e1 35 2f 5d c3 4a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Barys_GXQ_2147910133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Barys.GXQ!MTB"
        threat_id = "2147910133"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {51 50 57 ff 15 ?? ?? ?? ?? 6a 04 68 00 30 00 00 68 04 01 00 00 6a 00 57 ff 15 ?? ?? ?? ?? 6a 00 6a 11 68 ?? ?? ?? ?? 8b f0 56 57 ff 15}  //weight: 5, accuracy: Low
        $x_5_2 = {51 50 57 ff 54 24 ?? 6a 04 68 00 30 00 00 68 04 01 00 00 6a 00 57 ff 94 24 ?? ?? ?? ?? 6a 00 6a 11 68 ?? ?? ?? ?? 8b f0 56 57 ff 54 24}  //weight: 5, accuracy: Low
        $x_1_3 = "imgui_log.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Barys_MX_2147933715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Barys.MX!MTB"
        threat_id = "2147933715"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SafeExamBrowser" wide //weight: 1
        $x_1_2 = "tester" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Barys_NMD_2147936097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Barys.NMD!MTB"
        threat_id = "2147936097"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\War.txt" ascii //weight: 1
        $x_1_2 = "War by [WarGame,#eof] ( **** ti amo anche se tu non mi ricambi" ascii //weight: 1
        $x_1_3 = "Now it's fun" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "do you want to kill me" ascii //weight: 1
        $x_1_6 = "EncryptFileA" ascii //weight: 1
        $x_1_7 = "RegOpenKeyExA" ascii //weight: 1
        $x_1_8 = "RegSetValueExA" ascii //weight: 1
        $x_1_9 = "CreateMutexA" ascii //weight: 1
        $x_2_10 = "somesomeWar_EOF" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Barys_AB_2147939490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Barys.AB!MTB"
        threat_id = "2147939490"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5b b8 13 8d ff ff 80 34 03 b8 40 3d d6 fa ff ff 75 f4 61 e9 76 ?? ff ff 60 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Barys_AC_2147939492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Barys.AC!MTB"
        threat_id = "2147939492"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c0 89 08 50 45 43 6f 6d 70 61 63 74 32 00 ee 05 9e 8b c4 b7 67 3c 87 2f 7c e1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Barys_PGA_2147940183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Barys.PGA!MTB"
        threat_id = "2147940183"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 ec 89 45 ec 8b 4d 10 89 4d f0 ?? ?? 8b 55 f0 83 c2 ?? 89 55 f0 8b 45 10 05 ?? ?? ?? ?? 39 45 f0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

