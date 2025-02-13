rule TrojanDownloader_MSIL_Small_H_2147656829_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Small.H"
        threat_id = "2147656829"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "FacebookHack.exe" wide //weight: 10
        $x_10_2 = "firewall set opmode disable" wide //weight: 10
        $x_1_3 = "\\eriWemiL\\" wide //weight: 1
        $x_1_4 = "\\0002yeknoDe\\" wide //weight: 1
        $x_1_5 = "\\aazak\\" wide //weight: 1
        $x_1_6 = "\\retskorg\\" wide //weight: 1
        $x_1_7 = "\\suehprom\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Small_P_2147716652_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Small.P!bit"
        threat_id = "2147716652"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 6f 77 65 72 65 64 42 79 41 74 74 72 69 62 75 74 65 00 53 6d 61 72 74 41 73 73 65 6d 62 6c 79 2e 41 74 74 72 69 62 75 74 65 73}  //weight: 2, accuracy: High
        $x_2_2 = {4c 6f 61 64 00 67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e 00 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67}  //weight: 2, accuracy: High
        $x_2_3 = {53 6c 65 65 70 00 67 65 74 5f 45 6e 74 72 79 50 6f 69 6e 74}  //weight: 2, accuracy: High
        $x_1_4 = "hastebin.com/raw" wide //weight: 1
        $x_1_5 = {6d 00 6d 00 6c 00 75 00 63 00 65 00 2e 00 63 00 6f 00 6d 00 2f 00 2f 00 [0-48] 2e 00 74 00 78 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Small_Q_2147717432_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Small.Q!bit"
        threat_id = "2147717432"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" wide //weight: 1
        $x_1_2 = ">(.*)+)" wide //weight: 1
        $x_1_3 = {5c 00 74 00 6d 00 70 00 5c 00 69 00 64 00 [0-8] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Small_T_2147719007_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Small.T!bit"
        threat_id = "2147719007"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {64 00 6f 00 63 00 73 00 2e 00 67 00 6f 00 6f 00 67 00 6c 00 65 00 2e 00 63 00 6f 00 6d 00 2f 00 75 00 63 00 [0-16] 69 00 64 00 3d 00 [0-64] 65 00 78 00 70 00 6f 00 72 00 74 00 3d 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00}  //weight: 2, accuracy: Low
        $x_2_2 = {2e 00 70 00 68 00 70 00 [0-16] 69 00 64 00 3d 00 [0-32] 26 00 74 00 79 00 70 00 65 00 3d 00 [0-32] 26 00 74 00 65 00 78 00 74 00 3d 00}  //weight: 2, accuracy: Low
        $x_1_3 = {73 00 65 00 72 00 76 00 69 00 63 00 65 00 6d 00 61 00 6e 00 33 00 33 00 2e 00 72 00 75 00 2f 00 [0-32] 2e 00 6a 00 70 00 67 00}  //weight: 1, accuracy: Low
        $x_1_4 = {77 00 69 00 6e 00 33 00 32 00 5f 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 6f 00 72 00 [0-16] 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 6f 00 72 00 49 00 44 00}  //weight: 1, accuracy: Low
        $x_1_5 = "win32_logicaldisk.deviceid=" wide //weight: 1
        $x_1_6 = "VolumeSerialNumber" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Small_GM_2147759951_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Small.GM!MTB"
        threat_id = "2147759951"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 03 6f 1b 00 00 0a 7e ?? ?? ?? 04 03 7e ?? ?? ?? 04 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 d1}  //weight: 1, accuracy: Low
        $x_1_2 = {02 03 6f 1e 00 00 0a 7e ?? ?? ?? 04 03 7e ?? ?? ?? 04 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_MSIL_Small_GA_2147760280_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Small.GA!MTB"
        threat_id = "2147760280"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f fe 0a 18 [0-16] 73 ?? ?? ?? 0a 72 ?? ?? ?? 70 [0-32] 0a 73 ?? ?? ?? 0a [0-16] d0 ?? ?? ?? 01 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 [0-32] 0a 16 8c ?? ?? ?? 01 17 8d ?? ?? ?? 01 [0-32] 6f ?? ?? ?? 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {1f fe 13 04 [0-16] 73 ?? ?? ?? 0a 72 ?? ?? ?? 70 [0-32] 0a 73 ?? ?? ?? 0a [0-16] d0 ?? ?? ?? 01 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 [0-32] 0a 16 8c ?? ?? ?? 01 17 8d ?? ?? ?? 01 [0-32] 6f ?? ?? ?? 0a}  //weight: 1, accuracy: Low
        $x_1_3 = {1f fe 0d 18 [0-16] 73 ?? ?? ?? 0a 72 ?? ?? ?? 70 [0-32] 0a 73 ?? ?? ?? 0a [0-16] d0 ?? ?? ?? 01 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 [0-32] 0a 16 8c ?? ?? ?? 01 17 8d ?? ?? ?? 01 [0-32] 6f ?? ?? ?? 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_MSIL_Small_CDS_2147781753_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Small.CDS!MTB"
        threat_id = "2147781753"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "DeleteFileW" ascii //weight: 3
        $x_3_2 = "GetExecutingAssembly" ascii //weight: 3
        $x_3_3 = "InetCheck" ascii //weight: 3
        $x_3_4 = "@echo off" ascii //weight: 3
        $x_3_5 = "SelfDelete" ascii //weight: 3
        $x_3_6 = "ValidateRemoteCertificate" ascii //weight: 3
        $x_3_7 = "/C choice /C Y /N /D Y /T 0 & Del" wide //weight: 3
        $x_2_8 = "wireshark portable" ascii //weight: 2
        $x_2_9 = "sysinternals tcpview" ascii //weight: 2
        $x_2_10 = "anvir" ascii //weight: 2
        $x_2_11 = "Process Explorer" ascii //weight: 2
        $x_2_12 = "TaskManager" ascii //weight: 2
        $x_2_13 = "http analyzer stand-alone" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Small_AB_2147793979_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Small.AB!MTB"
        threat_id = "2147793979"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "MemberRefsProxy" ascii //weight: 3
        $x_3_2 = "WebResponse" ascii //weight: 3
        $x_3_3 = "HttpWebRequest" ascii //weight: 3
        $x_3_4 = "MTQzMw==" ascii //weight: 3
        $x_3_5 = "RVhQLkVYUE1BSU4=1Q" ascii //weight: 3
        $x_3_6 = "SmartAssembly" ascii //weight: 3
        $x_3_7 = "DebuggingModes" ascii //weight: 3
        $x_3_8 = "capx" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Small_MA_2147809186_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Small.MA!MTB"
        threat_id = "2147809186"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 2f 00 [0-96] 2f 00 43 00 72 00 61 00 62 00 43 00 68 00 65 00 61 00 74 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = "GetTempPath" ascii //weight: 1
        $x_1_3 = "HandleExecutor" wide //weight: 1
        $x_1_4 = "DownloadFile" ascii //weight: 1
        $x_1_5 = "DebuggableAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Small_ARAC_2147845925_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Small.ARAC!MTB"
        threat_id = "2147845925"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 09 06 09 91 03 11 04 91 08 1d 5f 62 d2 11 04 61 09 d6 20 ff 00 00 00 5f 61 b4 9c 11 04 17 d6 13 04 11 04 11 06 31 d8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Small_ABVQ_2147846883_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Small.ABVQ!MTB"
        threat_id = "2147846883"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0c 08 16 02 7b ?? 00 00 04 28 ?? 00 00 0a a2 00 08 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 06 28 ?? 00 00 0a 72 ?? ?? 00 70 18 16 8d ?? 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 07 74 ?? 00 00 01 72 ?? ?? 00 70 14 6f ?? 00 00 0a 26 00 2a}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Small_ASM_2147847934_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Small.ASM!MTB"
        threat_id = "2147847934"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 08 16 13 09 2b 43 11 08 11 09 9a 0d 00 09 6f ?? ?? ?? 0a 72 a5 00 00 70 6f ?? ?? ?? 0a 16 fe 01 13 0a 11 0a 2d 1c 00 12 02 08 8e 69 17 58 28 ?? ?? ?? 2b 00 08 08 8e 69 17 59 09 6f ?? ?? ?? 0a a2 00 00 11 09 17 58 13 09 11 09 11 08 8e 69 fe 04 13 0a 11 0a 2d af}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Small_ASM_2147847934_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Small.ASM!MTB"
        threat_id = "2147847934"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 06 25 28 ?? 00 00 0a 17 8d ?? 00 00 01 25 16 72 ?? 00 00 70 a2 28 ?? 00 00 0a 02 7b ?? 00 00 0a 28 ?? 00 00 0a 7d ?? 00 00 0a 18 8d ?? 00 00 01 25 16 72 ?? 00 00 70 a2 25 17 16 8c ?? 00 00 01 a2 16 16 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Small_ARAU_2147892011_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Small.ARAU!MTB"
        threat_id = "2147892011"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "\\72389 binder stub\\obj\\Debug\\72389 binder stub.pdb" ascii //weight: 2
        $x_2_2 = {04 20 ff 00 00 00 5f 2b 1d 03 6f ?? ?? ?? 0a 0c 2b 17 08 06 08 06 93 02 7b ?? ?? ?? 04 07 91 04 60 61 d1 9d 2b 03 0b 2b e0 06 17 59 25 0a 16 2f 02 2b 05 2b dd 0a 2b c8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Small_SG_2147900662_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Small.SG!MTB"
        threat_id = "2147900662"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GhostwritingNard" ascii //weight: 1
        $x_1_2 = "payloadPathOrURL" ascii //weight: 1
        $x_1_3 = "getETWPayload" ascii //weight: 1
        $x_1_4 = "downloadURL" ascii //weight: 1
        $x_1_5 = "BeginInvoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Small_MVA_2147902834_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Small.MVA!MTB"
        threat_id = "2147902834"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 18 00 00 0a 11 0b 7b 11 00 00 04 28 19 00 00 0a 28 02 00 00 06 2b 34}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Small_MVB_2147903175_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Small.MVB!MTB"
        threat_id = "2147903175"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 07 17 28 24 00 00 0a 28 25 00 00 0a 20 80}  //weight: 1, accuracy: High
        $x_1_2 = "DownloadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Small_MVC_2147905770_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Small.MVC!MTB"
        threat_id = "2147905770"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {17 8d 1a 00 00 01 0a 06 16 72 2d 00 00 70 a2 06 73 1e 00 00 0a 80 01 00 00 04}  //weight: 1, accuracy: High
        $x_1_2 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Small_MV_2147907304_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Small.MV!MTB"
        threat_id = "2147907304"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {17 8d 11 00 00 01 25 16 72 50 03 00 70 a2 28 15 00 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Small_SGA_2147913706_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Small.SGA!MTB"
        threat_id = "2147913706"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {07 11 05 02 11 05 91 09 61 08 11 04 91 61 b4 9c}  //weight: 4, accuracy: High
        $x_1_2 = "pr0t0typ3" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Small_SLE_2147917732_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Small.SLE!MTB"
        threat_id = "2147917732"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 72 63 00 00 70 02 6f 1c 00 00 0a 26 00 de 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Small_ABR_2147923698_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Small.ABR!MTB"
        threat_id = "2147923698"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {72 01 00 00 70 0a 28 02 00 00 06 00 28 04 00 00 0a 72 04 01 00 70 28 05 00 00 0a 0b 07 28 06 00 00 0a 26 72 9f 01 00 70 07 72 4c 02 00 70 28 05 00 00 0a 28 03 00 00 06 00 72 68 02 00 70 07 72 15 03 00 70 28 05 00 00 0a 28 03 00 00 06 00 72 31 03 00 70 07 28 07 00 00 0a 0c 72 d2 03 00 70 08 28 08 00 00 0a 26 20 60 ea 00 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Small_CCJC_2147923754_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Small.CCJC!MTB"
        threat_id = "2147923754"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 07 06 07 93 20 ?? ?? ?? ?? 65 20 ?? ?? ?? ?? 61 66 20 ?? ?? ?? ?? 58 61 d1 9d 07 20 ?? ?? ?? ?? 65 20 ?? ?? ?? ?? 58 59 25 0b 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 58 1d 63 2f c6}  //weight: 2, accuracy: Low
        $x_1_2 = {07 06 07 06 93 02 7b ?? ?? ?? ?? 04 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 61 66 5f 91 04 60 61 d1 9d 06 1d 66 18 63 66 59 25 0a 20 ?? ?? ?? ?? 65 20 ?? ?? ?? ?? 61 65 66 1c 62 2f c6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

