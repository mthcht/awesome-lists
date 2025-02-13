rule Ransom_Win32_RagnarLocker_DH_2147754419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/RagnarLocker.DH!MTB"
        threat_id = "2147754419"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "RagnarLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".ragnarok" ascii //weight: 1
        $x_1_2 = "cmd.exe /c vssadmin delete shadows /all /quiet" ascii //weight: 1
        $x_1_3 = "C:\\aaa_TouchMeNot_\\aaa_TouchMeNot_.txt" ascii //weight: 1
        $x_1_4 = "C:\\Mirc\\How_To_Decrypt_My_Files.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_RagnarLocker_MK_2147761027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/RagnarLocker.MK!MTB"
        threat_id = "2147761027"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "RagnarLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RAGNRPW" ascii //weight: 1
        $x_1_2 = "\\\\.\\PHYSICALDRIVE%d" ascii //weight: 1
        $x_1_3 = "!$R4GN4R" ascii //weight: 1
        $x_1_4 = "$!.txt" ascii //weight: 1
        $x_1_5 = "---END KEY" ascii //weight: 1
        $x_1_6 = "---BEGIN KEY" ascii //weight: 1
        $x_1_7 = ".ragn@r" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_RagnarLocker_MA_2147763121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/RagnarLocker.MA!MTB"
        threat_id = "2147763121"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "RagnarLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 8a 9c 35 ?? ?? ?? ?? 33 d2 0f b6 cb f7 75 0c 8b 45 08 0f b6 04 02 03 c7 03 c8 0f b6 f9 8a 84 3d 00 88 84 35 00 46 88 9c 3d 00 81 fe ?? ?? ?? ?? 72 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {40 8d 7f 01 0f b6 d0 89 55 14 8a 8c 15 ?? ?? ?? ?? 0f b6 c1 03 c3 0f b6 d8 8a 84 1d 00 88 84 15 00 8b 45 14 0f b6 d1 88 8c 1d 00 0f b6 8c 05 00 03 d1 0f b6 ca 0f b6 8c 0d 00 30 4f ff 83 ee ?? 75 af}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_RagnarLocker_B_2147763206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/RagnarLocker.B"
        threat_id = "2147763206"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "RagnarLocker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 8a 9c 35 ?? ?? ?? ?? 33 d2 0f b6 cb f7 75 0c 8b 45 08 0f b6 04 02 03 c7 03 c8 0f b6 f9 8a 84 3d ?? ?? ?? ?? 88 84 35 ?? ?? ?? ?? 46 88 9c 3d ?? ?? ?? ?? 81 fe 00 01 00 00 72 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {40 8d 7f 01 0f b6 d0 89 55 ?? 8a 8c 15 ?? ?? ?? ?? 0f b6 c1 03 c3 0f b6 d8 8a 84 1d ?? ?? ?? ?? 88 84 15 ?? ?? ?? ?? 8b 45}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b6 d1 88 8c 1d ?? ?? ?? ?? 0f b6 8c 05 ?? ?? ?? ?? 03 d1 0f b6 ca 0f b6 8c 0d ?? ?? ?? ?? 30 4f ff 83 ee 01 75 af}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_RagnarLocker_D_2147764221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/RagnarLocker.D!MTB"
        threat_id = "2147764221"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "RagnarLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 f0 8b 0c 0e 01 8c 05 ?? ?? ?? ?? 8b 94 05 00 8b ca c1 e9 ?? 88 4e ff 8b ca 88 94 05 ?? ?? ?? ?? 83 c0 ?? c1 e9 ?? c1 ea ?? 88 0e 88 56 01 83 f8 ?? 72 bd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_RagnarLocker_C_2147787717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/RagnarLocker.C!MTB"
        threat_id = "2147787717"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "RagnarLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 0c 57 42 81 f1 ?? ?? ?? ?? 03 f1 8b c6 c1 c0 ?? 2b f0 3b d3 7c e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_RagnarLocker_C_2147892048_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/RagnarLocker.C!dha"
        threat_id = "2147892048"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "RagnarLocker"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "error encrypt: %s" ascii //weight: 1
        $x_1_2 = "If you are reading this message, it means that: " ascii //weight: 1
        $x_1_3 = "D A R K    A N G E L S   T E A M  !" ascii //weight: 1
        $x_1_4 = "Cooperating with the FBI, CISA and so on" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

