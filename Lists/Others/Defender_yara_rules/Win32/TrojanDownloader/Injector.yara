rule TrojanDownloader_Win32_Injector_B_2147624397_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Injector.B"
        threat_id = "2147624397"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "www.2ppp.com" ascii //weight: 1
        $x_1_2 = {6a ff 6a 18 6a 0d 6a 0e 6a 06 6a 06 68 d4 07 00 00 8d 4d ?? c6 85 ?? ?? ff ff 07}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 70 08 8b 3d ?? ?? 40 00 68 ?? ?? 40 00 68 83 00 00 00 56}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Injector_C_2147624398_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Injector.C"
        threat_id = "2147624398"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 b8 fa 0f 00 00 e8 ?? ?? ff ff 50 53 e8 ?? ?? ff ff 68 01 02 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = "iexigub.sys" ascii //weight: 1
        $x_1_3 = "Msyjhxuc.exe" ascii //weight: 1
        $x_1_4 = "Mshucx.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Injector_ZA_2147925202_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Injector.ZA!MTB"
        threat_id = "2147925202"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {da 20 17 0d 6a cc 49 53 fe 54 b2 1f 52 79 08 71 59 b3 64 44 d0 5a 8b 19 95 6e 09 58 2e 4e 70 4d 9b 89 46 cf a4 5a 3c c5 74 5a ed c6 d3 bf 40 5c 79 9c bd 47 23 9b 5e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

