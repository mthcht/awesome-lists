rule Trojan_Win32_DLLSideLoad_SO_2147969828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DLLSideLoad.SO!MTB"
        threat_id = "2147969828"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DLLSideLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/cmd/backconnect_dll" ascii //weight: 1
        $x_2_2 = "://api1.mylabubus.shop/register" ascii //weight: 2
        $x_2_3 = "://api1.checkupdatesnow.xyz/register" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_DLLSideLoad_ST_2147973071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DLLSideLoad.ST!MTB"
        threat_id = "2147973071"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DLLSideLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 ec 04 89 45 e4 c6 45 9f 56 c6 45 a0 69 c6 45 a1 72 c6 45 a2 74 c6 45 a3 75 c6 45 a4 61 c6 45 a5 6c c6 45 a6 41 c6 45 a7 6c c6 45 a8 6c c6 45 a9 6f c6 45 aa 63 c6 45 ab 00 8d 45 9f 89 44 24 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DLLSideLoad_SJ_2147973313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DLLSideLoad.SJ!MTB"
        threat_id = "2147973313"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DLLSideLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 dc 31 c2 83 c0 01 83 f8 0a 89 55 dc 75 f0}  //weight: 1, accuracy: High
        $x_1_2 = {46 0f b6 1c 16 41 83 f3 b6 44 88 5d db 44 0f ?? 45 db 44 0f b6 4d db 46 88 1c 17}  //weight: 1, accuracy: Low
        $x_2_3 = {88 08 41 0f b6 c5 d1 f8 88 c1 83 f1 ad 41 80 e5 01 0f 44 c8 41 88 cd 41 31 d5 48 81 fb bf 0c 01 00 74 24}  //weight: 2, accuracy: High
        $x_5_4 = "sys_comp.dll" ascii //weight: 5
        $x_2_5 = {89 f1 0f b6 10 4b 8d 04 34 31 d1 88 08 40 0f b6 c6 d1 f8 89 c1 83 f1 ad 83 e6 01 0f 45 c1 41 83 c5 01 31 d0 41 81 fd c0 0c 01 00 89 c6}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

