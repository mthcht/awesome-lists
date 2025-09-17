rule TrojanDownloader_MSIL_Heracles_SIBA_2147794727_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Heracles.SIBA!MTB"
        threat_id = "2147794727"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe 0e 01 00 72 ?? ?? ?? ?? fe 0e 02 00 73 ?? ?? ?? ?? fe 0e 03 00 fe 0c 01 00 28 ?? ?? ?? ?? 6f ?? ?? ?? ?? fe 0e 04 00 38 ?? ?? ?? ?? fe 0d 04 00 28 ?? ?? ?? ?? fe 0e 05 00 fe 0c 05 00 28 ?? ?? ?? ?? fe 0c 02 00 28 ?? ?? ?? ?? da fe 0e 06 00 fe 0c 03 00 fe 0c 06 00 28 ?? ?? ?? ?? 6f ?? ?? ?? ?? 26 [0-16] fe 0d 04 00 28 ?? ?? ?? ?? fe 0e 07 00 fe 0c 07 00 3a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Heracles_ARA_2147837798_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Heracles.ARA!MTB"
        threat_id = "2147837798"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 04 11 05 09 11 05 09 8e 69 5d 91 08 11 05 91 61 d2 6f ?? ?? ?? 0a 11 05 17 58 13 05 11 05 08 8e 69 32 dc}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Heracles_ARAC_2147840697_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Heracles.ARAC!MTB"
        threat_id = "2147840697"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 09 06 09 8e 69 5d 91 08 06 91 61 d2 6f ?? ?? ?? 0a 06 1a 2c 04 17 58 0a 06 08 8e 69 32 e0}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Heracles_SR_2147841041_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Heracles.SR!MTB"
        threat_id = "2147841041"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 08 11 04 08 8e 69 5d 91 07 11 04 91 61 d2 6f 15 00 00 0a 11 04 17 58 13 04 11 04 07 8e 69 32 df}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Heracles_SS_2147841042_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Heracles.SS!MTB"
        threat_id = "2147841042"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 11 04 18 5b 07 11 04 18 6f 05 00 00 0a 1f 10 28 06 00 00 0a 9c 11 04 18 58 13 04 11 04 08 32 df}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Heracles_SU_2147844064_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Heracles.SU!MTB"
        threat_id = "2147844064"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0d 16 13 04 2b 1a 09 08 11 04 08 8e 69 5d 91 07 11 04 91 61 d2 6f 13 00 00 0a 11 04 17 58 13 04 11 04 07 8e 69 32 df}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Heracles_ARBE_2147846653_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Heracles.ARBE!MTB"
        threat_id = "2147846653"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 07 02 07 6f ?? ?? ?? 0a 7e ?? ?? ?? 04 07 1f 10 5d 91 61 07 20 ff 00 00 00 5d 28 ?? ?? ?? 06 61 28 ?? ?? ?? 06 9d 07 17 58 0b 07 02 6f ?? ?? ?? 0a 32 cc}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Heracles_CXJK_2147849617_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Heracles.CXJK!MTB"
        threat_id = "2147849617"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 63 00 72 00 79 00 70 00 74 00 31 00 2e 00 70 00 77}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Heracles_CXF_2147851251_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Heracles.CXF!MTB"
        threat_id = "2147851251"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 0b 00 00 0a 25 18 6f 0c 00 00 0a 25 18 6f 0d 00 00 0a 25 02 6f 0e 00 00 0a 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Heracles_VK_2147852422_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Heracles.VK!MTB"
        threat_id = "2147852422"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 8d 17 00 00 01 13 04 09 11 04 16 08 6f 13 00 00 0a 26 11 04 28 01 00 00 2b 28 02 00 00 2b 13 05 de 14}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Heracles_VM_2147891703_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Heracles.VM!MTB"
        threat_id = "2147891703"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 09 11 04 5d 13 0a 11 09 11 05 5d 13 0b 08 11 0a 91 13 0c 09 11 0b 6f ?? ?? ?? 0a 13 0d 08 11 09 17 58 11 04 5d 91 13 0e 11 0c 11 0d 61 11 0e 59 20 00 01 00 00 58 13 0f 08 11 0a 11 0f 20 00 01 00 00 5d d2 9c 11 09 17 59 13 09 11 09 16 2f af}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Heracles_VL_2147892532_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Heracles.VL!MTB"
        threat_id = "2147892532"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 09 07 8e 69 5d 91 08 09 08 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 07 09 17 58 07 8e 69 5d 91 59 20 00 01 00 00 58 13 07 07 09 07 8e 69 5d 11 07 20 00 01 00 00 5d d2 9c 09 15 58 0d 09 16 fe 04 16 fe 01 13 08 11 08 2d b7}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Heracles_CCEB_2147896586_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Heracles.CCEB!MTB"
        threat_id = "2147896586"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SELECT * FROM Win32_VideoController" wide //weight: 1
        $x_1_2 = "VMware" wide //weight: 1
        $x_1_3 = "/C taskkill /IM svchost.exe /F" wide //weight: 1
        $x_1_4 = "c:\\Users\\John\\Downloads" wide //weight: 1
        $x_1_5 = "Password" wide //weight: 1
        $x_1_6 = "ida64" wide //weight: 1
        $x_1_7 = "x64dbg" wide //weight: 1
        $x_1_8 = "x32dbg" wide //weight: 1
        $x_1_9 = "OLLYDBG" wide //weight: 1
        $x_1_10 = "WinDbg" wide //weight: 1
        $x_1_11 = "dnSpy\\dnSpy.xml" wide //weight: 1
        $x_1_12 = "Possible malicious activity detected! MalChk3 R1" wide //weight: 1
        $x_1_13 = "Windows\\System32\\drivers\\etc\\hosts" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Heracles_VO_2147897433_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Heracles.VO!MTB"
        threat_id = "2147897433"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0c 07 6f ?? ?? ?? 0a 69 0d 09 8d 2a 00 00 01 0a 38 15 00 00 00 07 06 08 09 6f ?? ?? ?? 0a 13 04 08 11 04 58 0c 09 11 04 59 0d 09 16 3d e4 ff ff ff dd 0d 00 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = "NEXUS.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Heracles_VP_2147901223_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Heracles.VP!MTB"
        threat_id = "2147901223"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Trademark - Lime" ascii //weight: 2
        $x_2_2 = "$LimeUSB\\LimeUSB.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Heracles_VQ_2147902567_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Heracles.VQ!MTB"
        threat_id = "2147902567"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 08 5d 0d 07 09 91 11 05 06 1f 16 5d 91 61 13 09 11 09 07 06 17 58 08 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d 13 0a 07 09 11 0a d2 9c 06 17 58 0a 06 08 11 06 17 58 5a fe 04 13 0b 11 0b 2d be}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Heracles_VS_2147915518_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Heracles.VS!MTB"
        threat_id = "2147915518"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 91 02 07 02 8e 69 5d 91 61 d2 9c 00 07 17 58 0b}  //weight: 2, accuracy: High
        $x_2_2 = "$aad35a1c-f41e-4829-af28-9388073c34f6" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Heracles_VT_2147917677_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Heracles.VT!MTB"
        threat_id = "2147917677"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "KutuphaneOtomasyonu.Properties" ascii //weight: 2
        $x_2_2 = "$09c26a9f-2d05-4a65-8ac1-a01ebdd7d012" ascii //weight: 2
        $x_1_3 = "tempuri.org/DataSetAAAAAAAAA.xsd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Heracles_VU_2147917685_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Heracles.VU!MTB"
        threat_id = "2147917685"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 06 06 9e 06 17 58 0a 06 20 ff 00 00 00 fe 03 16 fe 01 13 0d 11 0d 2d e7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Heracles_VU_2147917685_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Heracles.VU!MTB"
        threat_id = "2147917685"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {91 2b 3a 08 07 6f 19 00 00 0a 5d 6f 1a 00 00 0a 61 d2 9c 16 2d df 1a 2c dc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Heracles_SI_2147917731_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Heracles.SI!MTB"
        threat_id = "2147917731"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 b8 02 00 70 11 0a 6f ?? ?? ?? 0a 72 c4 02 00 70 11 05 6f ca 00 00 0a 72 d6 02 00 70 11 06 6f ?? ?? ?? 0a 13 0c 11 0c 72 ea 02 00 70 28 ?? ?? ?? 0a 11 07 6f 19 00 00 0a 28 c9 00 00 0a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Heracles_PAZ_2147917930_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Heracles.PAZ!MTB"
        threat_id = "2147917930"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {25 26 0b 72 [0-4] 07 28 ?? ?? ?? 06 25 26 0c 08 02 28 ?? ?? ?? 06 74 ?? ?? ?? ?? 28 ?? ?? ?? 06 0a 2b 00 06 2a}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Heracles_VV_2147921708_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Heracles.VV!MTB"
        threat_id = "2147921708"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 72 15 00 00 70 6f 18 00 00 0a 0a dd 0d 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Heracles_VV_2147921708_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Heracles.VV!MTB"
        threat_id = "2147921708"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 06 08 91 58 07 08 91 58 20 00 01 00 00 5d 0d 06 08 91 13 12 06 08 06 09 91 9c 06 09 11 12 9c 08 17 58 0c 08 20 00 01 00 00 32 d4}  //weight: 2, accuracy: High
        $x_2_2 = "$375c5eff-0650-4301-85ef-382cfefa9adf" ascii //weight: 2
        $x_2_3 = "VQP.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Heracles_SAK_2147923166_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Heracles.SAK!MTB"
        threat_id = "2147923166"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 05 12 06 28 1d 00 00 0a 09 08 11 04 18 6f 1e 00 00 0a 1f 10 28 1f 00 00 0a 6f 20 00 00 0a dd 0f 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Heracles_PRA_2147927164_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Heracles.PRA!MTB"
        threat_id = "2147927164"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 24 00 00 0a 0a 06 02 03 72 0d 00 00 70 28 25 00 00 0a 6f 26 00 00 0a de 0a 06 2c 06 06 6f 27 00 00 0a dc de 0e 28 28 00 00 0a 02 03 28 04 00 00 06 de 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Heracles_AYA_2147927994_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Heracles.AYA!MTB"
        threat_id = "2147927994"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Solara.exe" wide //weight: 2
        $x_1_2 = "This application requires administrative privileges." wide //weight: 1
        $x_1_3 = "/Obufscated/solara" wide //weight: 1
        $x_1_4 = "got ratted lmao their ip is" wide //weight: 1
        $x_1_5 = "CreateStartupShortcut" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Heracles_AYC_2147927996_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Heracles.AYC!MTB"
        threat_id = "2147927996"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "$b8abf173-0978-463e-a3fc-c" ascii //weight: 2
        $x_1_2 = "Malta Scanner" wide //weight: 1
        $x_1_3 = "SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC" wide //weight: 1
        $x_1_4 = "MicrosoftEdgeUpdateHistory.txt" wide //weight: 1
        $x_1_5 = "Optimizer.Properties.Resources" wide //weight: 1
        $x_1_6 = "TASKKILL" wide //weight: 1
        $x_1_7 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Heracles_SBK_2147948147_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Heracles.SBK!MTB"
        threat_id = "2147948147"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 01 11 05 16 11 06 6f 0f 00 00 0a 38 0a 00 00 00 38 05 00 00 00 38 e5 ff ff ff 11 04 11 05 16 11 05 8e 69 6f 10 00 00 0a 25 13 06 16 3d ce ff ff ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Heracles_SBK_2147948147_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Heracles.SBK!MTB"
        threat_id = "2147948147"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 09 00 00 06 25 11 00 28 01 00 00 0a 7d 02 00 00 04 6f 07 00 00 06 38 00 00 00 00 2a 7e 06 00 00 04 28 0f 00 00 06 28 0c 00 00 06 13 00 38 cd ff ff ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Heracles_C_2147949020_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Heracles.C!MTB"
        threat_id = "2147949020"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 10 11 10 72 8b 01 00 70 6f ?? 00 00 0a 26 de 0c 11 10 2c 07 11 10 6f ?? 00 00 0a dc}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Heracles_SK_2147952266_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Heracles.SK!MTB"
        threat_id = "2147952266"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 1a 00 00 06 7e 04 00 00 04 7e 05 00 00 04 28 0d 00 00 06 28 10 00 00 06 72 01 00 00 70 72 51 00 00 70 28 13 00 00 06 38 00 00 00 00 dd 10 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Heracles_SL_2147952365_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Heracles.SL!MTB"
        threat_id = "2147952365"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2b 07 2b 0c 18 2c f9 de 0d 28 0b 00 00 06 2b f2 0a 2b f1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

