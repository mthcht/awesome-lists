rule TrojanDownloader_Win32_GuloaderCrypt_SK_2147756894_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/GuloaderCrypt.SK!MTB"
        threat_id = "2147756894"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "GuloaderCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {29 c9 0f ee ca 43 0f e4 ca 0b 0f 0f ee ca 31 d9 0f da ca 39 c1 75 e9 0f e4 ca 0f ee ca}  //weight: 2, accuracy: High
        $x_2_2 = {0f da ca 0f e4 ca 81 c1 ?? ?? ?? ?? 0f e4 ca 0f ee ca 81 e9 ?? ?? ?? ?? 0f da ca 0f ee ca 81 f1 ?? ?? ?? ?? 0f e4 ca 0f ee ca 0f e4 ca 0f e4 ca ff 31}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_GuloaderCrypt_SN_2147759992_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/GuloaderCrypt.SN!MTB"
        threat_id = "2147759992"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "GuloaderCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {f8 fc ff d0 fc e8 ?? ?? ?? ?? 83 75 ?? 00 b9 00 00 00 00 83 34 24 00 83 04 24 00 ff 34 0a fc fc 81 34 24 ?? ?? ?? ?? 83 34 24 00 83 6d ?? 00 8f 04 08 83 34 24 00 fc 83 e9 fc 83 45 ?? 00 ff 45 ?? ff 4d ?? 81 f9 ?? ?? ?? ?? 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_GuloaderCrypt_SN_2147759992_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/GuloaderCrypt.SN!MTB"
        threat_id = "2147759992"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "GuloaderCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {ff 32 0f 38 0b e3 0f 38 0b e3 83 c2 04 0f 38 01 e3 0f 38 01 e3 bb ?? ?? ?? ?? 0f 38 08 e3 0f 38 01 e3 31 1c 24 90 0f 38 01 e3 8f 04 01 90 0f 38 0b e3 40 0f 38 0b e3 0f 38 08 e3 40 0f 38 08 e3 0f 38 0b e3 40 90 0f 38 08 e3 40 0f 38 08 e3 0f 38 0b e3 be ?? ?? ?? ?? 0f 38 08 e3 0f 38 01 e3 39 f0}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_GuloaderCrypt_MA_2147762419_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/GuloaderCrypt.MA!MTB"
        threat_id = "2147762419"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "GuloaderCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 45 20 ff 4d 20 83 04 24 ?? 48 83 34 24 00 83 75 20 00 39 08 75 e9}  //weight: 1, accuracy: Low
        $x_1_2 = {f8 83 34 24 ?? ff 34 0a 83 34 24 00 83 45 20 00 81 34 24 ?? ?? ?? ?? f8 83 04 24 00 8f 04 08 83 34 24 00 83 34 24 00 83 c1 ?? 83 75 20 00 f8 81 f9 ?? ?? ?? ?? 75 c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_GuloaderCrypt_SM_2147765444_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/GuloaderCrypt.SM!MTB"
        threat_id = "2147765444"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "GuloaderCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ff d0 0f 46 c0 0f 42 c0 ba ?? ?? ?? ?? 0f 43 c0 0f 4b c0 81 c2 ?? ?? ?? ?? 0f 46 c0 0f 42 c0 b9 ?? ?? ?? ?? 0f 43 c0 0f 43 c0 8b 1c 0a 0f 44 c0 0f 43 c0 81 f3 ?? ?? ?? ?? 0f 44 c0 0f 43 c0 31 1c 08 0f 46 c0 0f 4b c0 49 0f 47 c0 0f 42 c0 49 0f 43 c0 0f 44 c0 49 0f 42 c0 0f 4b c0 49 7d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

