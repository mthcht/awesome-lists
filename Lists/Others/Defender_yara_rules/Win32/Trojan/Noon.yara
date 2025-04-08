rule Trojan_Win32_Noon_A_2147724283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Noon.A"
        threat_id = "2147724283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Noon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 38 50 45 00 00 0f 85 ?? ?? ?? ?? 8d 45 84 ba 44 00 00 00 e8 ?? ?? ?? ?? 8d 45 c8 ba 10 00 00 00 e8 ?? ?? ?? ?? c7 45 84 44 00 00 00 66 c7 45 b4 00 00 c7 45 b0 01 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = ".0.0\\avpui.exe" ascii //weight: 1
        $x_1_3 = {43 3a 5c 00 2f 43 20 73 68 75 74 64 6f 77 6e 20 2d 66 20 2d 72 20 2d 74 20 30 00 00 63 6d 64 2e 65 78 65 00 6f 70 65 6e}  //weight: 1, accuracy: High
        $x_1_4 = "/c reg delete hkcu\\Environment /v windir /f && exit" ascii //weight: 1
        $x_1_5 = "bindedfiledropandexecute" ascii //weight: 1
        $x_1_6 = ".lnk\" \"C:\\Users\\" ascii //weight: 1
        $x_1_7 = "\\Bitdefender" ascii //weight: 1
        $x_1_8 = {76 62 63 00 [0-16] 53 65 6c 66 20 49 6e 6a 65 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Noon_QA_2147796261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Noon.QA!MTB"
        threat_id = "2147796261"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "algzifz" ascii //weight: 3
        $x_3_2 = "PathUnquoteSpacesA" ascii //weight: 3
        $x_3_3 = "SHRegDeleteEmptyUSKeyA" ascii //weight: 3
        $x_3_4 = "GopherFindFirstFileW" ascii //weight: 3
        $x_3_5 = "FtpGetFileA" ascii //weight: 3
        $x_3_6 = "RetrieveUrlCacheEntryFileA" ascii //weight: 3
        $x_3_7 = "FtpSetCurrentDirectoryA" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Noon_AV_2147805943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Noon.AV!MTB"
        threat_id = "2147805943"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "wspygzmh.pdb" ascii //weight: 3
        $x_3_2 = "urnspfpg" ascii //weight: 3
        $x_3_3 = "DisassociateColorProfileFromDeviceW" ascii //weight: 3
        $x_3_4 = "WNetGetResourceInformationW" ascii //weight: 3
        $x_3_5 = "vqklqja.dll" ascii //weight: 3
        $x_3_6 = "\\sobriety\\drag\\relating.mdb" ascii //weight: 3
        $x_3_7 = "miraculous.dll" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Noon_FB_2147808804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Noon.FB!MTB"
        threat_id = "2147808804"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "UrlCompareW" ascii //weight: 3
        $x_3_2 = "SHRegDeleteEmptyUSKeyW" ascii //weight: 3
        $x_3_3 = "midiOutCachePatches" ascii //weight: 3
        $x_3_4 = "InternetUnlockRequestFile" ascii //weight: 3
        $x_3_5 = "ParseX509EncodedCertificateForListBoxEntry" ascii //weight: 3
        $x_3_6 = "bpuzplozj" ascii //weight: 3
        $x_3_7 = "hwhoyd" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Noon_SIBA_2147814659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Noon.SIBA!MTB"
        threat_id = "2147814659"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Lexx@baklanov.net" ascii //weight: 1
        $x_1_2 = {8b 38 ff 57 ?? 8b 45 ?? 8b 16 0f b6 7c 10 ff a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? ba ?? ?? ?? ?? 2b d0 52 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 5a 92 8b ca 99 f7 f9 03 fa 8b d7 8d 45 ?? e8 ?? ?? ?? ?? 8b 55 07 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? ff 06 ff 4d ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Noon_GVA_2147938152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Noon.GVA!MTB"
        threat_id = "2147938152"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {89 d1 44 20 c1 08 d0 30 c8 44 08 c2 30 c2 74 20}  //weight: 3, accuracy: High
        $x_2_2 = {0f 94 c2 08 d1 44 30 c2 44 30 c1 80 f1 01 08 d1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

