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

rule Trojan_Win32_DLLSideLoad_SJ_2147973279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DLLSideLoad.SJ!MTB"
        threat_id = "2147973279"
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
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

