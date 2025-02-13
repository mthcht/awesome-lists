rule TrojanDownloader_Win64_IcedID_ADC_2147782081_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/IcedID.ADC!MTB"
        threat_id = "2147782081"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "qpgvshruf" ascii //weight: 3
        $x_3_2 = "rgcyvadze" ascii //weight: 3
        $x_3_3 = "uquaughzq" ascii //weight: 3
        $x_3_4 = "ywowfmaqd" ascii //weight: 3
        $x_3_5 = "GetFinalPathNameByHandleW" ascii //weight: 3
        $x_3_6 = "CommandLineToArgvW" ascii //weight: 3
        $x_3_7 = "DllRegisterServer" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_IcedID_ADC_2147782081_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/IcedID.ADC!MTB"
        threat_id = "2147782081"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "AlOLYNePc" ascii //weight: 3
        $x_3_2 = "AxWbctmvAxmHwJmbUl" ascii //weight: 3
        $x_3_3 = "BafAFGjAlKbclKHABC" ascii //weight: 3
        $x_3_4 = "DQNOrkpuLktW" ascii //weight: 3
        $x_3_5 = "WriteConsoleW" ascii //weight: 3
        $x_3_6 = "IsValidLocale" ascii //weight: 3
        $x_3_7 = "EnumSystemLocalesW" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_IcedID_ZZ_2147786592_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/IcedID.ZZ"
        threat_id = "2147786592"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 8a 04 33 41 0f b6 d3 44 8d 42 01 83 e2 03 41 83 e0 03 42 8a 4c 85 e0 02 4c 95 e0 32 c1 42 8b 4c 85 e0 41 88 04 1b 83 e1 07 8b 44 95 e0 49 ff c3 d3 c8 ff c0 89 44 95 e0 83 e0 07 8a c8 42 8b 44 85 e0 d3 c8 ff c0 42 89 44 85 e0 48 8b 5d c8 4c 3b 5d d0 73 06 48 8b 75 c0 eb a4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_IcedID_ZY_2147786594_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/IcedID.ZY"
        threat_id = "2147786594"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "0123456789ABCDEF" ascii //weight: 1
        $x_1_2 = {42 8a 04 02 02 c2 48 ff c2 c0 c0 03 0f b6 c8 8b c1 83 e1 0f 48 c1 e8 04 42 0f be 04 18 66 42 89 04 53 42 0f be 0c 19 66 42 89 4c 53 02 49 83 c2 02 49 3b d1 72 ca}  //weight: 1, accuracy: High
        $x_1_3 = {0f b6 c8 49 ff c0 8b c1 83 e1 0f 48 c1 e8 04 0f be 04 10 66 43 89 04 4b 0f be 04 11 66 43 89 44 4b 02 49 83 c1 02 41 8a 00 84 c0 75 d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_IcedID_ZX_2147786596_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/IcedID.ZX"
        threat_id = "2147786596"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 48 81 ec b0 00 00 00 31 c0 89 c1 c7 ?? ?? ?? ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 35 ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? c7 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 89 ?? ?? ?? c7 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 35 ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? c7 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 8b ?? ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 41 89 ?? 48 89 ?? ?? ?? 4c 89 ?? 41 b8 00 30 00 00 41 b9 04 00 00 00 4c 8b ?? ?? ?? 41 ff d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_IcedID_CA_2147786727_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/IcedID.CA!MTB"
        threat_id = "2147786727"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 44 24 ?? 8a 08 88 4c 24 ?? c7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 48 8b 44 24 ?? 48 05 01 00 00 00 48 89 44 24 ?? c7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 8a 4c 24 ?? 0f b6 d1 83 ea ?? 88 54 24 ?? c7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 8a 4c 24 ?? 44 0f b6 c1 41 c1 e0 04 44 88 44 24 ?? c7 44 24 ?? ?? ?? ?? ?? 8a 4c 24 ?? 88 4c 24 ?? c7 44 24 ?? ?? ?? ?? ?? 48 8b 44 24 ?? 8a 08 88 4c 24 ?? c7 44 24 ?? ?? ?? ?? ?? 48 8b 44 24 ?? 48 05 01 00 00 00 48 89 44 24 ?? c7 44 24 ?? ?? ?? ?? ?? 8a 4c 24 ?? 44 0f b6 c9 41 83 e9 ?? 44 88 4c 24}  //weight: 1, accuracy: Low
        $x_1_2 = {45 09 d3 44 88 5c 24 ?? c7 44 24 ?? ?? ?? ?? ?? 8a 4c 24 ?? 44 0f b6 d1 8a 4c 24 ?? 0f b6 f1 44 31 d6 40 88 74 24 ?? c7 44 24 ?? ?? ?? ?? ?? 8a 4c 24 ?? 80 c1 01 88 4c 24 ?? c7 44 24 ?? ?? ?? ?? ?? 8a 4c 24 ?? 48 8b 44 24 ?? 88 08 c7 44 24 ?? ?? ?? ?? ?? 48 8b 44 24 ?? 48 05 01 00 00 00 48 89 44 24 ?? c7 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_IcedID_ZW_2147786820_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/IcedID.ZW"
        threat_id = "2147786820"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_100_2 = {83 e2 03 41 83 e0 03 [0-1] 8a ?? ?? ?? [0-1] 02 ?? ?? ?? [0-1] 32 [0-2] 42 8b 4c ?? ?? 41 88 04 1b 83 e1 07 8b 44 ?? ?? 49 ff c3 d3 c8 ff c0 89 44 ?? ?? 83 e0 07 8a c8 42 8b 44 ?? ?? d3 c8 ff c0 42 89 44 ?? ?? 48 8b [0-3] 4c 3b [0-3] 73}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_IcedID_ZV_2147789199_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/IcedID.ZV"
        threat_id = "2147789199"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_100_2 = {8d 81 59 2e 00 00 d1 c8 d1 c8 c1 c8 02 35 1d 15 00 00 c1 c0 02 d1 c0 c3}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_IcedID_GIM_2147810960_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/IcedID.GIM!MTB"
        threat_id = "2147810960"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 94 24 80 00 00 00 ff ca 48 2b f7 8b cb 8b c3 83 e0 01 d1 e9 03 c0 83 e1 01 0b c8 8b c3 25 fc ff 00 00 ff c3 0b c8 8b c2 83 c1 0f 48 23 c8 42 8a 04 31 32 04 3e 88 07 48 ff c7 3b dd 72 cd}  //weight: 10, accuracy: High
        $x_10_2 = {8a 53 01 c0 e2 03 8a 0b 80 e1 07 0a d1 c0 e2 03 8a 43 ff 24 07 0a d0 43 88 14 08 4c 03 c7 48 8d 5b 03 49 81 f8 00 04 00 00 0f 8d 98 00 00 00 4c 8b 0d 57 bb 01 00 eb c8}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_IcedID_VP_2147819441_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/IcedID.VP!MTB"
        threat_id = "2147819441"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {41 0f b6 d3 44 8d 42 01 83 e2 ?? 41 83 e0 ?? 42 8a 44 84 40 02 44 94 40 43 32 04 33 42 8b 4c 84 40 41 88 04 1b 83 e1 07 8b 44 94 40 49 ff c3 d3 c8 ff c0 89 44 94 40 83 e0 ?? 8a c8 42 8b 44 84 40 d3 c8 ff c0 42 89 44 84 40 48 8b 5c 24 28 4c 3b 5c 24 30 73 07 4c 8b 74 24 20 eb a3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_IcedID_ZU_2147840525_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/IcedID.ZU"
        threat_id = "2147840525"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = "{e3f38493-f850-4c6e-a48e-1b5c1f4dd35f}" ascii //weight: 10
        $x_10_3 = "{0ccac395-7d1d-4641-913a-7558812ddea2}" ascii //weight: 10
        $x_10_4 = "{d65f4087-1de4-4175-bbc8-f27a1d070723}" ascii //weight: 10
        $x_10_5 = {48 83 ec 28 ba 01 00 00 00 83 c9 ff ff 15 ?? ?? ?? ?? eb f0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

