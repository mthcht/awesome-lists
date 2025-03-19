rule Trojan_Win32_NanoBot_VB_2147751602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NanoBot.VB!MTB"
        threat_id = "2147751602"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NanoBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zdoaVFMaNG6k7vt141" wide //weight: 1
        $x_1_2 = "x3bfpN860KlyClyh30" wide //weight: 1
        $x_1_3 = "UjxfR1Zp4uwihAhZvk121" wide //weight: 1
        $x_1_4 = "ui4AdK2R4mSCb7BFHOY230" wide //weight: 1
        $x_1_5 = "PaYNu4Rz8tNyWZHCGirIJnPX79UIZ234" wide //weight: 1
        $x_1_6 = "uibmcEOwQKOWrtg1egEMtpYOBAWyFMwGVeFRK65" wide //weight: 1
        $x_1_7 = "nkSXMych9Hbiwvd2ULvlRD6fh8uFAWecU162" wide //weight: 1
        $x_1_8 = "ojRtdXP2rPNF5tlOIKjTMRhg5XbcALahnwNWY206" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NanoBot_SMW_2147773620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NanoBot.SMW!MTB"
        threat_id = "2147773620"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NanoBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8d 94 0d 00 fe ff ff 0f b6 34 10 0f b6 12 33 db 3b f2 74 0e 43 8b fe 33 fb 3b fa 75 f7 bf ff 01 00 00 89 9c 8d 04 f6 ff ff 41 3b cf}  //weight: 2, accuracy: High
        $x_1_2 = "oYvesRKGsy.exe" ascii //weight: 1
        $x_1_3 = "MnRpexjxup.vbs" ascii //weight: 1
        $x_1_4 = "XbLABtoKOd.lnk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NanoBot_MA_2147812287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NanoBot.MA!MTB"
        threat_id = "2147812287"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NanoBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f8 02 75 21 12 00 b8 03 00 00 00 e8 [0-11] 43 8d 43 14 e8 ?? ?? ?? ?? 8b d0 80 c2 61 8d 45 f8 e8 ?? ?? ?? ?? 8b 55 f8 8d 45 fc e8 ?? ?? ?? ?? 83 fb 06 75}  //weight: 1, accuracy: Low
        $x_1_2 = {53 31 db 69 93 08 90 40 00 05 84 08 08 42 89 93 08 90 40 00 f7 e2 89 d0 5b c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NanoBot_CL_2147838673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NanoBot.CL!MTB"
        threat_id = "2147838673"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NanoBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 8d 38 ff ff ff 83 c1 ?? 89 8d 38 ff ff ff 8b 55 ac 0f b7 42 06 39 85 38 ff ff ff 7d ?? 8b 8d 70 ff ff ff 8b 95 70 ff ff ff 8b b5 54 ff ff ff 03 72 14 8b 85 70 ff ff ff 8b 7d f4 03 78 0c 8b 49 10 f3 a4 8b 8d 70 ff ff ff 83 c1 28 89 8d 70 ff ff ff eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NanoBot_RB_2147844483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NanoBot.RB!MTB"
        threat_id = "2147844483"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NanoBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 4d f9 8a 4d fa 8a 55 fb 32 4d fe 32 55 ff 34 dd 88 45 f8 88 4d fa 88 55 fb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NanoBot_RC_2147844484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NanoBot.RC!MTB"
        threat_id = "2147844484"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NanoBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Project\\MyRatServer\\Release\\MyRatServer.pdb" ascii //weight: 1
        $x_1_2 = "32177921-9F67-42e7-BE1F-73F104777885" wide //weight: 1
        $x_1_3 = "LG Uplus,.CO.LTD" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

