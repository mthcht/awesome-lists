rule Backdoor_Win32_ParalaxRat_STB_2147776250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/ParalaxRat.STB"
        threat_id = "2147776250"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "ParalaxRat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b c1 83 e0 1f 8a 44 05 dc 30 81 ?? ?? ?? ?? 41 81 f9 00 60 00 00 72 e8 b8 ?? ?? ?? ?? ff d0}  //weight: 5, accuracy: Low
        $x_1_2 = {b0 36 00 00 7c ?? 42 81 fa 80 fc 0a 00 7c ?? c7 45 dc}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 40 68 00 60 00 00 68 ?? ?? ?? ?? ff 55 f4 c7 45 f0 ?? ?? ?? ?? ff 65 f0}  //weight: 1, accuracy: Low
        $x_2_4 = {3d 40 1f 00 00 7c ee 42 81 fa b0 8f 06 00 7c e3 c7 45 d0 [0-10] c7 45 d4 ?? ?? ?? ?? c7 45 d8 ?? ?? ?? ?? c7 45 dc}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_ParalaxRat_STC_2147776251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/ParalaxRat.STC"
        threat_id = "2147776251"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "ParalaxRat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 34 6a 00 6a 00 6a 00 6a 13 6a 3a ff 75 0c ff 75 08 e8}  //weight: 1, accuracy: High
        $x_1_2 = {8b 7d fc 89 44 8f fc 2d 04 04 04 04 49 75 f1}  //weight: 1, accuracy: High
        $x_1_3 = {8a 14 0e 88 14 0f 41 83 f9 20 [0-32] 8a 14 0e 88 14 0f 41}  //weight: 1, accuracy: Low
        $x_1_4 = {88 14 30 02 ca [0-16] 8d 64 24 0c 30 0e}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 75 fc 8a 14 0e 02 04 1f 02 c2 8a 34 06 88 34 0e 88 14 06 5e fe c1 75}  //weight: 1, accuracy: High
        $x_1_6 = {5f 3b a2 e5 [0-16] f7 de 22 5a [0-16] da 6f ad b7 [0-16] 4a cd 4a f5}  //weight: 1, accuracy: Low
        $x_1_7 = {bc fa de 5c [0-16] a5 52 ef cd [0-16] ee 14 de fc [0-16] df 73 aa bc}  //weight: 1, accuracy: Low
        $x_2_8 = {5b 00 43 00 74 00 72 00 6c 00 [0-255] 5b 00 41 00 6c 00 74 00 [0-255] 43 00 6c 00 69 00 70 00 62 00 6f 00 61 00 72 00 64 00 20 00 53 00 74 00 61 00 72 00 74 00 [0-255] 43 00 6c 00 69 00 70 00 62 00 6f 00 61 00 72 00 64 00 20 00 45 00 6e 00 64 00}  //weight: 2, accuracy: Low
        $x_2_9 = "DeleteFile(Wscript.ScriptFullName)" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_ParalaxRat_STD_2147777266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/ParalaxRat.STD"
        threat_id = "2147777266"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "ParalaxRat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/coFG/G7r2k4" ascii //weight: 1
        $x_1_2 = "4D5A6B65726E656C333200005045" ascii //weight: 1
        $x_1_3 = "<block2>0</block2>" ascii //weight: 1
        $x_1_4 = "xmr_mine_stop" ascii //weight: 1
        $x_1_5 = "remotebrowser_info" ascii //weight: 1
        $x_1_6 = "KEYLOG: " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Win32_ParalaxRat_STD_2147777266_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/ParalaxRat.STD"
        threat_id = "2147777266"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "ParalaxRat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/coFG/G7r2k4" ascii //weight: 1
        $x_1_2 = "spm21.net" ascii //weight: 1
        $x_1_3 = "xmr_mine_stop" ascii //weight: 1
        $x_1_4 = "hvnc_start" ascii //weight: 1
        $x_1_5 = "klgonlinestart" ascii //weight: 1
        $x_1_6 = "shell_exec" ascii //weight: 1
        $x_1_7 = "screenlive_stop" ascii //weight: 1
        $x_1_8 = "remotebrowser" ascii //weight: 1
        $x_1_9 = "uac_bypass" ascii //weight: 1
        $x_1_10 = "usb_spread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Backdoor_Win32_ParalaxRat_DM_2147786459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/ParalaxRat.DM!MTB"
        threat_id = "2147786459"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "ParalaxRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 44 8d ec 83 e8 08 6b c0 1f 99 f7 fe 8d 04 16 99 f7 fe 88 54 0d e8 41 89 4d a0}  //weight: 10, accuracy: High
        $x_10_2 = {c6 46 24 00 8a cb 80 e1 01 74 16 8a 4d 0c 80 c9 01 0f b6 c1 8b ce 50 8d 44 24 13}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_ParalaxRat_Q_2147812254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/ParalaxRat.Q!MTB"
        threat_id = "2147812254"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "ParalaxRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0f b6 c8 33 c0 01 4e 04 40 c7 44 96 0c 02 00 00 00}  //weight: 5, accuracy: High
        $x_5_2 = {8b 55 08 33 c0 8b 4d 0c c7 44 8a 0c 02 00 00 00 ff 42 04 40 89 44 8a 0c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

