rule Trojan_Win64_LummaStealer_AB_2147888447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.AB!MTB"
        threat_id = "2147888447"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "201"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_100_2 = {0f b6 3c 02 89 d9 80 e1 18 d3 e7 89 c1 83 e1 fc 31 7c 0c 14 40 83 c3 08 39 c6 75 e4}  //weight: 100, accuracy: High
        $x_100_3 = {8d 1c ed 00 00 00 00 89 d9 80 e1 18 80 c9 07 31 c0 40 d3 e0 89 e9 83 e1 3c 31 44 0c 14 83 fe 38}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_KAA_2147894571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.KAA!MTB"
        threat_id = "2147894571"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "thoseintroductory.exe" ascii //weight: 1
        $x_1_2 = "callcustomerpro.exe" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_IP_2147894962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.IP!MTB"
        threat_id = "2147894962"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c1 8b 0c 24 48 8b 54 24 20 88 04 0a}  //weight: 1, accuracy: High
        $x_1_2 = "GPUView.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_NL_2147897386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.NL!MTB"
        threat_id = "2147897386"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {45 0f 57 ff 4c 8b 35 48 31 9a 00 65 4d 8b 36 4d 8b 36 48 8b 04 24 48 8b 5c 24 50 48 01 d8}  //weight: 2, accuracy: High
        $x_1_2 = {49 8b 4e 30 c6 81 e5 00 00 00 01 48 8b 0d 3d 69 90 00 48 83 39 00 0f 85 16 02 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_NL_2147897386_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.NL!MTB"
        threat_id = "2147897386"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {74 29 8b 05 ?? ?? ?? ?? 65 48 8b 0c 25 ?? ?? ?? ?? 48 8b 04 c1 4c 8b 80 ?? ?? ?? ?? 48 8b 0d 46 b0 2e 00 31 d2}  //weight: 5, accuracy: Low
        $x_1_2 = "maninternmentsrijibmaninternment" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_NL_2147897386_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.NL!MTB"
        threat_id = "2147897386"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "writerfunctionpro.exe" ascii //weight: 1
        $x_1_2 = "timeprogrammer.exe" ascii //weight: 1
        $x_1_3 = "SendEffectively" wide //weight: 1
        $x_1_4 = "DecryptFileA" ascii //weight: 1
        $x_1_5 = "DelNodeRunDLL32" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_CCHG_2147901937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.CCHG!MTB"
        threat_id = "2147901937"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 98 48 8b d0 48 8d 4c 24 ?? e8 ?? ?? ?? ?? 0f b6 00 48 8b 4c 24 ?? 48 8b 94 24 ?? ?? ?? ?? 48 03 d1 48 8b ca 0f b6 09 33 c8 8b c1 48 8b 4c 24 ?? 48 8b 94 24 ?? ?? ?? ?? 48 03 d1 48 8b ca 88 01 e9}  //weight: 1, accuracy: Low
        $x_1_2 = {48 63 04 24 48 8b 4c 24 ?? 0f b7 04 41 89 44 24 ?? 8b 04 24 99 b9 ?? ?? ?? ?? f7 f9 8b c2 83 c0 ?? 8b 4c 24 04 33 c8 8b c1 48 63 0c 24 48 8b 54 24 ?? 66 89 04 4a eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_NS_2147902328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.NS!MTB"
        threat_id = "2147902328"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {41 0f b7 0a 0f 83 ee 0e fc ff 66 41 89 01 48 8d 64 24 ?? e9 f5 31 fc ff}  //weight: 3, accuracy: Low
        $x_3_2 = {e8 51 3c fd ff 33 c9 48 f7 54 24 ?? 4d 85 d2 48 8d 64 24 ?? 0f 84 74 7d fe ff}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_NS_2147902328_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.NS!MTB"
        threat_id = "2147902328"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b 1d b1 33 43 00 48 8d 05 82 b5 23 00 48 8d 0d 3d cd 19 00 bf 04 00 00 00 48 8d 35 01 57 1a 00 41 b8 19 00 00 00 45 31 c9}  //weight: 2, accuracy: High
        $x_1_2 = {48 8b 3a 48 8b 72 08 31 c0 48 8d 1d cb d1 19 00 b9 04 00 00 00 e8 a3 a3 d1 ff 48 89 9c 24 28 02 00 00 48 89 84 24 20 02 00 00 48 8d 05 1f dc 19 00 bb 07 00 00 00 48 8d 8c 24 10 02 00 00 bf 02 00 00 00 48 89 fe e8 12 66 dd ff e8 6d 77 dd ff 48 8b ac 24 60 05 00 00 48 81 c4 68 05 00 00 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_NLK_2147904080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.NLK!MTB"
        threat_id = "2147904080"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 83 ec 18 4c 8b c1 b8 4d 5a 00 00 66 39 05 ?? ?? ?? ?? 75 78 48 63 0d ?? ?? ?? ?? 48 8d 15 cd 70 cf ff 48 03 ca}  //weight: 3, accuracy: Low
        $x_3_2 = {66 0f 6f 05 8d a4 12 00 48 83 c8 ff f3 0f 7f 05 ?? ?? ?? ?? 48 89 05 12 0f 14 00 f3 0f 7f 05 ?? ?? ?? ?? 48 89 05 1b 0f 14 00 c6 05 ?? ?? ?? ?? 01 b0 01 48 83 c4}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_CB_2147916862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.CB!MTB"
        threat_id = "2147916862"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "main.RedirectToPayload" ascii //weight: 2
        $x_1_2 = "main.LoadPEModule" ascii //weight: 1
        $x_1_3 = "main.GetNTHdrs" ascii //weight: 1
        $x_1_4 = "main.AllocPEBuffer" ascii //weight: 1
        $x_1_5 = "main.PERawToVirtual" ascii //weight: 1
        $x_1_6 = "main.CreateSuspendedProcess" ascii //weight: 1
        $x_1_7 = "main._LoadPEModule" ascii //weight: 1
        $x_1_8 = "main.Resume_Thread" ascii //weight: 1
        $x_1_9 = "main.Write_ProcessMemory" ascii //weight: 1
        $x_1_10 = "main.Get_ThreadContext" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_AMW_2147919022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.AMW!MTB"
        threat_id = "2147919022"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {41 ff c1 49 63 c9 8a 04 19 41 88 04 1a 44 88 1c 19 41 0f b6 0c 1a 49 03 cb 0f b6 c1 8a 0c 18 41 30 0e 49 ff c6 48 83 ef 01 75 a9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_NM_2147920281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.NM!MTB"
        threat_id = "2147920281"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {33 c9 48 89 4c 24 30 89 4c 24 38 49 ba 70 d1 54 54 6f 07 a8 e8 48 21 4c 24 20 44 8d 49 0c 8d 51 01 48 8b c8 48 8b c7 4c 8d 44 24 30 ff 15 ff 73 03 00}  //weight: 3, accuracy: High
        $x_2_2 = {85 c0 74 08 8a 44 24 38 24 01 eb 06 32 c0 eb 02 b0 01 48 8b 4c 24 40 48 33 cc e8 c8 c2 fa ff 48 8b 5c 24 60 48 83 c4 50}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_GV_2147920749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.GV!MTB"
        threat_id = "2147920749"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.Md5Encode" ascii //weight: 1
        $x_5_2 = "main.EUkcKYTIDb" ascii //weight: 5
        $x_1_3 = "main.TerminateProcess" ascii //weight: 1
        $x_5_4 = "main.nlZMziDMqv" ascii //weight: 5
        $x_1_5 = "main.CreateSuspendedProcess" ascii //weight: 1
        $x_1_6 = "main.ResumeThread" ascii //weight: 1
        $x_1_7 = "main.WriteProcessMemory" ascii //weight: 1
        $x_1_8 = "main.Wow64SetThreadContext" ascii //weight: 1
        $x_1_9 = "main.GetThreadContext" ascii //weight: 1
        $x_5_10 = "LwNOrAxUVY/main.go" ascii //weight: 5
        $x_1_11 = "main.nwPXANdvbL" ascii //weight: 1
        $x_1_12 = "main.qWwvfeKaCT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_DB_2147921600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.DB!MTB"
        threat_id = "2147921600"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cb c1 e9 02 ff c1 44 6b c1 32 8b cb 83 e1 03 6b d1 32 83 c2 0a}  //weight: 1, accuracy: High
        $x_1_2 = {48 89 7c 24 ?? 48 89 44 24 ?? 48 89 74 24 ?? 4c 89 7c 24 ?? c7 44 24 ?? ?? ?? ?? ?? c7 44 24 ?? ?? ?? ?? ?? 44 89 44 24 ?? 89 54 24 ?? 41 b9 ?? ?? ?? ?? 4d 8b 06 48 8d 15 ?? ?? ?? ?? 33 c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_YAB_2147921679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.YAB!MTB"
        threat_id = "2147921679"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 0f b6 44 3e 01 0f b6 4c 05 30 43 0f b6 44 3e 02 0f b6 54 05 30 43 0f b6 44 3e 03 44 0f b6 44 05 30 49 83 c6 04 c1 e7 06 03 f9 c1 e7 06 03 fa c1 e7 06 41 03 f8}  //weight: 1, accuracy: High
        $x_10_2 = {44 30 27 48 ff c7 49 83 ef 01 0f 85}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_VV_2147921877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.VV!MTB"
        threat_id = "2147921877"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "test_lib/main.go" ascii //weight: 5
        $x_1_2 = "main.qHbLKcVFPY" ascii //weight: 1
        $x_1_3 = "main.BnMWnpUycO" ascii //weight: 1
        $x_1_4 = "main.HFdrQcLRTh" ascii //weight: 1
        $x_1_5 = "main.HwNcTblZxJ" ascii //weight: 1
        $x_1_6 = "main.khgzBwOcdS" ascii //weight: 1
        $x_1_7 = "main.RDF" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_LummaStealer_GM_2147921911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.GM!MTB"
        threat_id = "2147921911"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "main.cFVvJaclpr" ascii //weight: 4
        $x_1_2 = "main.oepNeSmKgT" ascii //weight: 1
        $x_1_3 = "main.Md5Encode" ascii //weight: 1
        $x_4_4 = "main.cQPubDNZNj" ascii //weight: 4
        $x_1_5 = "main.RDF" ascii //weight: 1
        $x_1_6 = "main.neJDPbLRWD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_LummaStealer_VM_2147921951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.VM!MTB"
        threat_id = "2147921951"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.RDF" ascii //weight: 1
        $x_2_2 = "main.VZCOQzehCp" ascii //weight: 2
        $x_1_3 = "main.WjLRMuNaor" ascii //weight: 1
        $x_2_4 = "main.EFTcmUgEtT" ascii //weight: 2
        $x_1_5 = "main.faqLSRWRlV" ascii //weight: 1
        $x_2_6 = "main.lnejYwfZkm" ascii //weight: 2
        $x_1_7 = "main.iiQhNBnnfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_LummaStealer_VVG_2147922956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.VVG!MTB"
        threat_id = "2147922956"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.Md5Encode" ascii //weight: 1
        $x_1_2 = "main.RDF" ascii //weight: 1
        $x_1_3 = "main.randSeq" ascii //weight: 1
        $x_8_4 = "main.KwPMHzDibl" ascii //weight: 8
        $x_1_5 = "main._Cfunc_wrf" ascii //weight: 1
        $x_1_6 = "main.TerminateProcess" ascii //weight: 1
        $x_1_7 = "main.CreateSuspendedProcess" ascii //weight: 1
        $x_1_8 = "main.WriteProcessMemory" ascii //weight: 1
        $x_1_9 = "main._RunPE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_8_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_LummaStealer_EM_2147932659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.EM!MTB"
        threat_id = "2147932659"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "I02Op2e6ZD52OJInVolF/WhWwGUgukvawTLHcS4qp" ascii //weight: 1
        $x_1_2 = "PWGVuoIBdb/core_injector.go" ascii //weight: 1
        $x_1_3 = "PWGVuoIBdb/injection.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_NITA_2147935434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.NITA!MTB"
        threat_id = "2147935434"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {66 44 39 34 41 74 6a ff 15 75 82 07 00 85 c0 74 5c 48 8b 4d 30 4c 8d 45 38 48 8d 55 30 ff c3 e8 9e e6 ff ff 8b c8 85 c0 78 0f 48 8b 4d 30 48 85 c9 74 48 48 8b 45 38 eb c7}  //weight: 2, accuracy: High
        $x_2_2 = {48 8d 4c 24 78 48 8d 1d 03 89 07 00 ff 15 8d 5d 07 00 0f b7 44 24 78 48 8d 0d e9 88 07 00 bf 05 00 00 00 85 c0}  //weight: 2, accuracy: High
        $x_2_3 = "stimulate.exe" wide //weight: 2
        $x_2_4 = "Deleting file" ascii //weight: 2
        $x_2_5 = "extract payloads" ascii //weight: 2
        $x_2_6 = "Connected to elevated engine" ascii //weight: 2
        $x_1_7 = "DecryptFileW" ascii //weight: 1
        $x_1_8 = "UnmapViewOfFile" ascii //weight: 1
        $x_1_9 = "load a decryption method" ascii //weight: 1
        $x_1_10 = "rollback is disabled" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_PIN_2147936194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.PIN!MTB"
        threat_id = "2147936194"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ff c2 48 63 c2 48 8d 8c 24 00 01 00 00 48 03 c8 0f b6 01 43 88 04 08 44 88 11 43 0f b6 0c 08 49 03 ca 0f b6 c1 0f b6 8c 04 ?? ?? ?? ?? 30 0f 48 ff c7 49 83 eb 01 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_2147937061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.MTR!MTB"
        threat_id = "2147937061"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTR: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 48 8b 04 25 60 00 00 00 48 89 84 24 80 01 00 00 48 8b 84 24 80 01 00 00 48 8b 40 18 48 89 84 24 78 01 00 00 48 8b 84 24 78 01 00 00 48 8b 40 20 48 89 84 24 68 01 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_PG_2147937708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.PG!MTB"
        threat_id = "2147937708"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {40 80 f6 00 45 08 da 40 80 ce 00 41 80 f2 ff 41 20 f2 41 88 fb 41 80 f3 ff 40 88 de 44 20 de 80 f3 ff 40 20 df 40 08 fe 45 88 d3 41 20 f3 41 30 f2 45 08 d3 41 f6 c3 01 b8 37 89 da 81 b9 29 a3 60 75 0f 45 c8 89 4c 24 64 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_BU_2147938333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.BU!MTB"
        threat_id = "2147938333"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 31 f5 48 f7 d1 4c 09 c3 48 21 cb 48 09 eb 48 f7 d0 48 31 c3 48 f7 d3 48 21 c3 48 89 5c 24}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_LBT_2147938397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.LBT!MTB"
        threat_id = "2147938397"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 c1 f6 d1 80 e1 46 24 b9 08 c8 89 c1 80 f1 55 34 aa 89 ca 80 e2 fe 24 ?? 80 e1 ?? 08 c1 89 d0 20 c8 30 d1 08 c1 89 c8 f6 d0 24 67 80 e1 98 08 c1 80 f1 98 b8 ad 08 0c 30 41 0f 44 c6 3d ac 08 0c 30 0f 8f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_BV_2147938910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.BV!MTB"
        threat_id = "2147938910"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {20 c8 08 d9 20 da 08 c2 89 c8 30 d0}  //weight: 3, accuracy: High
        $x_2_2 = {30 d0 20 d8 40 20 f1 20 d3 08 cb 89 c1 30 d9 b9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_GVC_2147939293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.GVC!MTB"
        threat_id = "2147939293"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 30 d9 30 d3 80 f2 01 44 08 c2 80 f2 01 08 da 89 c3}  //weight: 2, accuracy: High
        $x_1_2 = {44 30 c3 44 08 c1 80 f1 01 08 d9 89 cb 30 d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_GVD_2147939342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.GVD!MTB"
        threat_id = "2147939342"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 30 c0 44 89 c2 80 f2 01 20 c2}  //weight: 2, accuracy: High
        $x_1_2 = {0f 9c c0 41 30 c0 44 89 c2 f6 d2 20 c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_BW_2147939533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.BW!MTB"
        threat_id = "2147939533"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {30 da 08 c3 80 f3 01 08 d3 89 da 20 ca 80 f3 01 40 20 fb 08 d3 89 ca 30 c2 08 c1 80 f1 01 08 d1}  //weight: 3, accuracy: High
        $x_2_2 = {30 c2 20 ca 44 20 c3 20 c1 08 d9 89 d3 30 cb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_BY_2147939567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.BY!MTB"
        threat_id = "2147939567"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {31 c8 f7 d2 09 c2 69 c2 95 e9 d1 5b 69 4c 24 64 95 e9 d1 5b 41 89 cd 41 31 c5 44 21 e9 41 21 c5 89 c8 44 21 e8 41 31 cd 41 09 c5 8b 44 24 68 83 c0 01 89 44 24 24}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_SHJI_2147940262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.SHJI!MTB"
        threat_id = "2147940262"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 83 ec 18 48 8d 6c 24 10 48 8b 05 a4 93 ff ff 48 31 e8 48 89 45 00 8b 0d 33 a4 ff ff 8b 05 31 a4 ff ff 8d 71 ff 0f af f1 89 f1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_DQ_2147940284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.DQ!MTB"
        threat_id = "2147940284"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f 9f c2 30 d1 89 d3 20 c3 30 c2 08 da 89 cb 30 d3 84 d2 b8 ?? ?? ?? ?? ba ?? ?? ?? ?? 0f 45 c2 84 c9 0f 45 c2 84 db b9 ?? ?? ?? ?? e9}  //weight: 10, accuracy: Low
        $x_10_2 = {0f 9f c1 89 c2 30 ca 20 c1 08 d1 89 cb 30 d3 84 c9 b8 ?? ?? ?? ?? b9 ?? ?? ?? ?? 0f 45 c1 84 d2 0f 44 c1 84 db b9 ?? ?? ?? ?? e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_LummaStealer_GVE_2147940366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.GVE!MTB"
        threat_id = "2147940366"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 08 95 e9 d1 5b 89 cb c1 eb 18 31 cb 69 cb 95 e9 d1 5b 69 ff 95 e9 d1 5b 31 cf 48 83 c0 04 83 c2 fc 83 fa 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_CZ_2147940573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.CZ!MTB"
        threat_id = "2147940573"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 48 8b 04 25 60 00 00 00 48 8b 40 18 48 8b 40 20 48 89 84 24 08 02 00 00 8b 05 f6 81 03 00 8d 48 ff 0f af c8 f6 c1 01 b8 f9 69 e4 ce b9 76 13 e6 8a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_GVH_2147940779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.GVH!MTB"
        threat_id = "2147940779"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f af e8 40 f6 c5 01 0f 94 c0 0f 94 44 24 2f 83 f9 0a 0f 9c c1 0f 9c 44 24 3f 08 c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_GVI_2147940780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.GVI!MTB"
        threat_id = "2147940780"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f af e8 40 f6 c5 01 0f 94 44 24 2c 83 fa 0a 0f 9c 44 24 2d 4d 89 ce 4d 89 c5 48 89 ce}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_GVJ_2147940878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.GVJ!MTB"
        threat_id = "2147940878"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 70 ff 0f af f0 40 f6 c6 01 0f 94 44 24 22 83 fa 0a 0f 9c 44 24 23 48 89 ce ba}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_GVK_2147940879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.GVK!MTB"
        threat_id = "2147940879"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f af c8 f6 c1 01 0f 94 c0 0f 94 45 1f 41 83 fa 0a 0f 9c c2 0f 9c 45 2f 08 c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_TL_2147940918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.TL!MTB"
        threat_id = "2147940918"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 c3 41 b8 05 4c 1d 48 41 bd f8 c5 1f 90 45 0f 45 c5 bf 05 4c 1d 48 41 0f 45 fc be 82 1c dd b4 41 0f 45 f7 b8 c0 73 72 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_DZ_2147940931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.DZ!MTB"
        threat_id = "2147940931"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {42 0f b6 04 27 4c 89 ef 44 8b 6d 98 0f b6 0c 1e 01 c1 0f b6 c1 48 8b 4d b0 0f b6 04 01 48 63 4d f0 48 8b 55 88 30 04 0a 44 8b 65 f0 41 83 c4 01 b8}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_NP_2147941081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.NP!MTB"
        threat_id = "2147941081"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 63 45 18 42 80 34 30 bc 8b 45 18 83 c0 01 89 45 88}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_ZSS_2147941156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.ZSS!MTB"
        threat_id = "2147941156"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {44 89 f6 4d 89 fe 4d 89 ef 48 8d 7d f8 41 bd 0b 29 05 4d 01 c1 0f b6 c1 48 8b 4d ?? 0f b6 04 01 48 63 4d f0 41 30 04 0f 44 8b 65 ?? 41 83 c4 01 b8 c5 bc 26 c3 3d d1 c3 86 f7 0f 8e ?? ?? ?? ?? e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_GVL_2147941185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.GVL!MTB"
        threat_id = "2147941185"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0f b6 01 30 d0 88 44 24 27 44 89 cd}  //weight: 3, accuracy: High
        $x_3_2 = {48 63 45 24 42 80 34 30 35 8b 45 24 83 c0 01 89 45 1c 8b 05 ?? ?? ?? ?? 8d 48 ?? 0f af c8}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_LummaStealer_NTS_2147941271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.NTS!MTB"
        threat_id = "2147941271"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {43 0f b6 0c 01 01 c1 0f b6 c1 48 8b 4d ?? 8a 04 01 48 63 4d ec 48 8b 55 98 30 04 0a 44 8b 6d ec 41 83 c5 01 b8 fa 3d f7 cc 3d 62 fa 3e f1 0f 8e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_SFH_2147941275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.SFH!MTB"
        threat_id = "2147941275"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 63 45 34 42 80 34 30 44 8b 45 34 83 c0 01 89 45 2c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_SMK_2147941279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.SMK!MTB"
        threat_id = "2147941279"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 89 d4 41 89 cd 48 8b 05 f8 6d 03 00 48 31 e8 48 89 45 00 8b 05 cb 7b 03 00 8b 0d c9 7b 03 00 8d 50 ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_RA_2147941416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.RA!MTB"
        threat_id = "2147941416"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 b8 55 e4 28 b2 b8 67 2a af 5f 44 0f 44 c0 bb eb a2 46 1d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_SLBP_2147941626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.SLBP!MTB"
        threat_id = "2147941626"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 83 ec 38 48 8d 6c 24 30 0f 29 7d f0 0f 29 75 e0 48 8b 05 8c ad 02 00 48 31 e8 48 89 45 d8 8b 05 57 ba 02 00 8b 0d 55 ba 02 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_GVM_2147941894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.GVM!MTB"
        threat_id = "2147941894"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 01 30 d0 88 44 24 27 44 89 ce e9}  //weight: 2, accuracy: High
        $x_1_2 = {44 30 c2 48 8b 84 24 d0 08 00 00 88 10 48 8b 84 24 a0 03 00 00 48 83 c0 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_BSA_2147942014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.BSA!MTB"
        threat_id = "2147942014"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {75 69 48 8b 48 40 84 01 48 8b 50 48 48 8d 35 b3 04 00 00 48 89 b4 24}  //weight: 10, accuracy: High
        $x_1_2 = {49 3b 66 10 76 25 55 48 89 e5 48 83 ec 08 4d 8b 66 20 4d 85 e4 75 1b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_BSA_2147942014_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.BSA!MTB"
        threat_id = "2147942014"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {48 83 ec 28 e8 9f f6 ?? ?? e8 a6 b9 ff ff 8b c8 48 83 c4 28}  //weight: 8, accuracy: Low
        $x_3_2 = {48 8d 0d 51 42 03 00 e8 08 8d 00 00 85 c0 74 0a [0-22] 00 48 8d 0d 88 41 03 00 e8 a3 8c 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_LZL_2147942228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.LZL!MTB"
        threat_id = "2147942228"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 c1 0f b6 c1 0f b6 84 04 ?? ?? ?? ?? 48 63 4c 24 70 48 8b 54 24 28 30 04 0a 8b 5c 24 70 83 c3 01 b8 b8 63 b9 78 3d 67 c8 35 0e 0f 8f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_NFU_2147942239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.NFU!MTB"
        threat_id = "2147942239"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell -Command \"Add-MpPreference -ExclusionPath" ascii //weight: 1
        $x_1_2 = "powershell -Command \"Invoke-WebRequest -Uri" ascii //weight: 1
        $x_2_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 2
        $x_1_4 = "Windows Defender" ascii //weight: 1
        $x_1_5 = "C:\\Users\\danar\\source\\repos\\opretorsa\\x64\\Release\\opretorsa.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_BC_2147942490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.BC!MTB"
        threat_id = "2147942490"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {c1 e9 18 31 c1 69 c1 95 e9 d1 5b 69 4c 24 68 95 e9 d1 5b 31 c1 89 4c 24 5c 8b 44 24 6c 83 c0 01 89 44 24}  //weight: 3, accuracy: High
        $x_1_2 = {4c 8b 02 8b 4a 08 4c 89 00 89 48 08 c3}  //weight: 1, accuracy: High
        $x_1_3 = {4a 0f be 84 09 ?? ?? ?? ?? 42 8a 8c 09 ?? ?? ?? ?? 48 2b d0 8b 42 fc d3 e8 41 89 40 20 48 8d 42 04 49 89 50 08 8b 0a 41 89 48 24 8b 4c 24 60 ff c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_GZZ_2147942592_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.GZZ!MTB"
        threat_id = "2147942592"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 de 81 fb ?? ?? ?? ?? 0f 85 ?? ?? ?? ?? 0f b6 19 30 d3 88 5c 24 27 44 89 d6}  //weight: 10, accuracy: Low
        $x_10_2 = {44 89 d5 81 ff ?? ?? ?? ?? ?? ?? 89 fd 81 ff ?? ?? ?? ?? ?? ?? 0f b6 19 30 d3 88 5c 24 27 44 89 f5 eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_LummaStealer_GZM_2147942637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.GZM!MTB"
        threat_id = "2147942637"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 19 30 d3 88 5c 24 ?? 44 89 ce e9 ?? ?? ?? ?? 8a 5c 24 ?? 48 8b 4c 24 28 48 31 e1 e8 ?? ?? ?? ?? 89 d8 48 83 c4}  //weight: 10, accuracy: Low
        $x_10_2 = {89 f3 81 fe 2e 9b 32 57 0f 85 ?? ?? ?? ?? 0f b6 01 30 d0 88 44 24 ?? 44 89 fb e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_LummaStealer_PGJ_2147942647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.PGJ!MTB"
        threat_id = "2147942647"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c1 e9 0d 33 4c 24 ?? 69 c9 ?? ?? ?? ?? 89 ca c1 ea ?? 31 ca 89 54 24 ?? 8b 0d ?? ?? ?? ?? 8d 51 ff 0f af d1 f6 c2 01 ba ?? ?? ?? ?? 0f 44 d3 83 3d ?? ?? ?? ?? ?? 0f 4c d3 81 fa ?? ?? ?? ?? 0f 8f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_YAK_2147942758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.YAK!MTB"
        threat_id = "2147942758"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d ab 30 f1 93 0f 8e ?? ?? ?? ?? 3d 66 bd 2d 9a 0f 8e ?? ?? ?? ?? 3d 67 bd 2d 9a}  //weight: 1, accuracy: Low
        $x_1_2 = {0f af c8 f6 c1 01 b8 25 f4 dd 44 b9 29 b0 01 38}  //weight: 1, accuracy: High
        $x_10_3 = {48 8b 4d b8 0f b6 04 01 48 63 4d f0 48 8b 55 90 30 04 0a 8b 5d f0 83 c3 01}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_NR_2147942887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.NR!MTB"
        threat_id = "2147942887"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 72 6f 63 65 73 73 20 22 [0-47] 2e 65 78 65 22 20 2d 46 6f 72 63 65}  //weight: 2, accuracy: Low
        $x_2_2 = "BExplorer Launcher" ascii //weight: 2
        $x_1_3 = "ExecutionPolicyRead after Close" ascii //weight: 1
        $x_1_4 = "127.0.0.1:53" ascii //weight: 1
        $x_1_5 = "powershell" ascii //weight: 1
        $x_1_6 = "BypassHidden" ascii //weight: 1
        $x_1_7 = "Command" ascii //weight: 1
        $x_1_8 = "Hidden" ascii //weight: 1
        $x_1_9 = "Decrypt" ascii //weight: 1
        $x_1_10 = "KeyLogWriter" ascii //weight: 1
        $x_1_11 = "hangupkilled" ascii //weight: 1
        $x_1_12 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_BG_2147943162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.BG!MTB"
        threat_id = "2147943162"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 54 24 24 89 44 24 60 8a c2 32 44 24 34 0f b6 c0 66 a3 ?? ?? ?? 00 8b 44 24 70 03 c3 a3 ?? ?? ?? 00 3b 44 24 4c 75}  //weight: 3, accuracy: Low
        $x_2_2 = {32 c1 8b 4c 24 40 32 44 24 11 30 04 11 42 8b 44 24 24 40 89 54 24 14 89 44 24 24 81 fa}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_PGLG_2147943193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.PGLG!MTB"
        threat_id = "2147943193"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 c1 0f b6 c1 48 8b 4d ?? 8a 04 01 48 63 4d ?? 41 30 04 ?? 8b 45 ?? 83 c0 ?? 89 45 ?? 8b 05 ?? ?? ?? ?? 8d 48 ff 0f af c8 f6 c1 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_PGLC_2147943228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.PGLC!MTB"
        threat_id = "2147943228"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 c1 30 d1 20 c1 44 20 c3 20 d0 08 d8 89 ca 30 c2 ba ?? ?? ?? ?? bb ?? ?? ?? ?? 0f 45 d3 8b 6f ?? 84 c0 89 d0 0f 45 c3 89 ac 24}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_PGLI_2147943822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.PGLI!MTB"
        threat_id = "2147943822"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 0c 3b 01 c1 0f b6 c1 48 8b 4d ?? 8a 04 01 48 63 4d ?? 48 8b 55 ?? 30 04 0a 8b 45 ?? 83 c0 ?? 89 45 ?? 8b 05 ?? ?? ?? ?? 8d 48 ff 0f af c8 f6 c1}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_BOE_2147943833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.BOE!MTB"
        threat_id = "2147943833"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 c1 0f b6 c1 8a 84 04 ?? ?? ?? ?? 48 63 4c 24 64 48 8b 54 24 30 30 04 0a 8b 7c 24 64 83 c7 01 b8 5b b4 35 56 41 bf 4f aa 0b 2b 41 bd 46 5b d6 f4 8b 6c 24 2c 3d 14 16 d6 0b 0f 8e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_PGLS_2147944137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.PGLS!MTB"
        threat_id = "2147944137"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 f8 c1 e8 0d 31 f8 69 c0 ?? ?? ?? ?? 89 c6 c1 ee ?? 31 c6 48 8b 4c 24 ?? 48 31 e1 e8 ?? ?? ?? ?? 89 f0 48 83 c4 ?? 5b 5d 5f 5e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_PGLS_2147944137_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.PGLS!MTB"
        threat_id = "2147944137"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 c1 0f b6 c1 0f b6 84 04 ?? ?? ?? ?? 48 63 4c 24 ?? 48 8b 54 24 ?? 30 04 0a 8b 7c 24 ?? 83 c7 01 b8 ?? ?? ?? ?? 3d ?? ?? ?? ?? 0f 8f ?? ?? ?? ?? e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_PGLS_2147944137_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.PGLS!MTB"
        threat_id = "2147944137"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f 94 c0 0f 95 c1 83 3d ?? ?? ?? ?? 0a 0f 9c c3 30 d9 80 f1 01 89 da 08 c2 80 f2 01 08 ca 89 c1 30 d9 20 c8 20 d9 89 c3 80 f3 01 30 c8 80 f1 01 08 d9 80 f1 01 08 c1}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_PGLS_2147944137_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.PGLS!MTB"
        threat_id = "2147944137"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 63 44 24 ?? 48 8b 4c 24 20 69 04 81 95 e9 d1 5b 89 c1 c1 e9 ?? 31 c1 69 c1 95 e9 d1 5b 69 5c 24 ?? 95 e9 d1 5b 31 c3 8b 6c 24 ?? 83 c5 ?? 41 ba ?? ?? ?? ?? 41 81 fa ?? ?? ?? ?? 0f 8f ?? ?? ?? ?? e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_PGLS_2147944137_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.PGLS!MTB"
        threat_id = "2147944137"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 c1 0f b6 c1 48 8b 4d ?? 0f b6 04 01 48 63 4d ?? 41 30 04 0e 44 8b 75 ?? 41 83 c6 01 b8 ?? ?? ?? ?? 3d ?? ?? ?? ?? 0f 8f}  //weight: 5, accuracy: Low
        $x_5_2 = {01 c1 0f b6 c1 0f b6 84 04 ?? ?? ?? ?? 48 63 4c 24 ?? 48 8b 54 24 ?? 30 04 0a 8b 74 24 ?? 83 c6 01 b8 ?? ?? ?? ?? 3d ?? ?? ?? ?? 0f 8f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_LummaStealer_PP_2147944296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.PP!MTB"
        threat_id = "2147944296"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 89 8c 24 ?? 00 00 00 48 8d 0d 29 58 15 00 48 89 8c 24 ?? 00 00 00 48 8b 1d aa 99 34 00 48 8d 05 43 74 15 00 48 8d 8c 24 ?? 00 00 00 bf 01 00 00 00 48 89 fe e8 ce 78 eb ff 48 81 c4 28 01 00 00}  //weight: 2, accuracy: Low
        $x_1_2 = "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v AdobeUpdater /t REG_SZ /d \"%s\" /f" ascii //weight: 1
        $x_1_3 = "cmd.exe /c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_MMJ_2147944424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.MMJ!MTB"
        threat_id = "2147944424"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 c1 0f b6 c1 8a 84 04 ?? ?? ?? ?? 48 63 4c 24 7c 48 8b 54 24 40 30 04 0a 44 8b 7c 24 7c 41 83 c7 01 b8 8a 0c a5 74 8b 7c 24 3c 8b 5c 24 38 44 8b 6c 24 34 3d a5 83 70 0d 0f 8f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_MZX_2147944524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.MZX!MTB"
        threat_id = "2147944524"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 c1 0f b6 c1 8a 84 04 ?? ?? ?? ?? 48 63 4c 24 ?? 48 8b 54 24 40 30 04 0a 8b 7c 24 ?? 83 c7 01 b8 40 83 d0 1a 45 89 fe 8b 74 24 ?? 8b 5c 24 30 3d c8 41 b1 35 0f 8f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_MZC_2147944637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.MZC!MTB"
        threat_id = "2147944637"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 c1 8a 84 04 a0 01 00 00 48 63 4c 24 ?? 4c 8b 4c 24 38 41 30 04 09 44 8b 44 24 ?? 41 83 c0 01 b8 19 73 39 06 41 89 ef 41 ba 45 f3 d3 a7 be a6 f1 40 3e 41 bb fd 1d d5 f9 bd 86 7a 2c cf 41 bd e0 dd 42 3e 3d 87 3a 27 0b 0f 8f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_TRD_2147945335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.TRD!MTB"
        threat_id = "2147945335"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 c1 0f b6 c1 8a 84 04 ?? 01 00 00 48 63 8c 24 88 00 00 00 41 30 04 0e 8b 84 24 88 00 00 00 83 c0 01 89 44 24 74 8b 05 ?? ?? ?? ?? 8d 48 ff 0f af c8 f6 c1 01 b8 6f d3 a3 d3 b9 e9 b6 aa 85 e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_BLM_2147946563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.BLM!MTB"
        threat_id = "2147946563"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 c1 0f b6 c1 0f b6 84 04 ?? ?? ?? ?? 48 63 4c 24 68 41 30 04 0c 8b 74 24 68 83 c6 01 b8 a2 61 8f 4b 3d c5 6a b1 f3 0f 8f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_PGG_2147947943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.PGG!MTB"
        threat_id = "2147947943"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 c1 0f b6 c1 [0-10] 48 63 [0-10] 30 04 [0-2] 8b [0-10] 83 ?? 01 [0-10] b8 [0-12] 3d [0-8] 0f 8f ?? ?? ff ff e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_GAPO_2147948284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.GAPO!MTB"
        threat_id = "2147948284"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_8_1 = {bf 05 a1 f3 44 08 56 c7 26 21 2d bd b4 9a 34 65 eb 5b 2f}  //weight: 8, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_GAPO_2147948284_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.GAPO!MTB"
        threat_id = "2147948284"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_8_1 = {61 a8 63 c8 37 1f 1d 05 6f c0 fc d8 ed a5 4e ee cd f0 2f f7 11 99 da 13 53 d9 24 f9 f9 b8 9e 1e fd e0 f0 19 83 9d 13 cf 4d b3 c6 0a fc 8a 92 53 c4 0a 76 fa 40 59 4a db 82 e6 7d 1e 72 4f 7c 61}  //weight: 8, accuracy: High
        $x_1_2 = ".eye" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_ZZS_2147948851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.ZZS!MTB"
        threat_id = "2147948851"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 fa 8b d7 0f af d1 8b ca 81 f1 23 e4 05 4f 2b c8 8b c1 89 85 ?? ?? ?? ?? 66 c7 44 24 30 00 00 66 c7 44 24 28 f7 00 0f b7 05 5e f1 38 00 66 89 44 24 20 45 33 c9 66 41 b8 11 00 33 d2 33 c9 e8 ?? ?? ?? ?? 88 05 08 f0 38 00 0f b6 05 3e f0 38 00 0f b7 8d 84 02 00 00 3b c8 74}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_C_2147948875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.C!MTB"
        threat_id = "2147948875"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 0f af fe 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 48 f7 ef 48 c1 fa ?? 49 89 f8 48 c1 ff ?? 48 29 fa 48 6b d2 ?? 49 29 d0 4a 8d 0c 06 e9}  //weight: 3, accuracy: Low
        $x_2_2 = {48 85 c9 48 0f 4c ca 48 ff c1 48 89 d8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_PAHB_2147949538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.PAHB!MTB"
        threat_id = "2147949538"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {55 48 89 e5 48 81 ec c0 02 00 00 48 8d 15 dc cd 08 00 48 89 94 24 10 02 00 00 48 8d 15 5d 5c 17 00 48 89 94 24 18 02 00 00 48 c7 84 24 68 02 00 00 00 00 00 00 48 8d 15 52 08 00 00 48 89 94 24 50 02 00 00 48 c7 84 24 60 02 00 00 01 00 00 00 48 c7 84 24 68 02 00 00 01 00 00 00 48 8d 94 24 10 02 00 00 48 89 94 24 58 02 00 00 48 8b 05 4b ed 3a 00 31 db}  //weight: 2, accuracy: High
        $x_1_2 = "-sendAll_ip" ascii //weight: 1
        $x_1_3 = "-shutdown" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_2_5 = "Realtek_HD_Audio_Universal_Service_Driver.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_PLS_2147949621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.PLS!MTB"
        threat_id = "2147949621"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "-NoProfile -ExecutionPolicy Bypass -Command \"" ascii //weight: 2
        $x_2_2 = "Add-MpPreference -ExclusionPath" ascii //weight: 2
        $x_1_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 34 00 31 00 2e 00 39 00 38 00 2e 00 36 00 2e 00 31 00 33 00 30 00 3a 00 35 00 35 00 35 00 34 00 2f 00 [0-31] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = {68 74 00 74 00 70 3a 2f 2f 31 34 31 2e 39 38 2e 36 2e 31 33 30 3a 35 35 35 34 2f [0-31] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_5 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 38 00 34 00 2e 00 32 00 31 00 2e 00 31 00 38 00 39 00 2e 00 32 00 32 00 3a 00 35 00 35 00 35 00 34 00 2f 00 [0-31] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_6 = {68 74 00 74 00 70 3a 2f 2f 38 34 2e 32 31 2e 31 38 39 2e 32 32 3a 35 35 35 34 2f [0-31] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_LummaStealer_GAPA_2147950170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.GAPA!MTB"
        threat_id = "2147950170"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_8_1 = {78 69 e5 29 d3 e7 65 b1 e1 39 31 d3 fd a5 d0 79 e2 0e 7a 63 2c 9c f6 e5 80 7a f7 ac da ec ce a1 c0 88 5d 8d ff 9f 4d a4 b3 9f 03}  //weight: 8, accuracy: High
        $x_8_2 = {5d de d6 2e 79 1a 63 40 55 a9 98 c5 fb 75 d2 aa 8b 60 7d 0a 7c 11 7d 7b 16 d5 20 45 7e 6e d8 54 36 b0 e8 a4 cc 5c 88 24 0b bb 5f 1e 3f 17 fb ae 25 6a 49 3d e1 56 88 5f be 61 49 58}  //weight: 8, accuracy: High
        $x_1_3 = ".oep" ascii //weight: 1
        $x_1_4 = ".ilt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_8_*) and 1 of ($x_1_*))) or
            ((2 of ($x_8_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_LummaStealer_GAPC_2147950282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.GAPC!MTB"
        threat_id = "2147950282"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_8_1 = {09 c8 51 1b 9d 90 5f 9f 66 ae 45 57 c8 9c 68 a0 d1 d0 1c f5 df 7d b2 4d 82 fe f5 15 5c e8 0c 31 0d 4c 76 a4 6b 8e 6f 45 75 36 63}  //weight: 8, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_GAPJ_2147950959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.GAPJ!MTB"
        threat_id = "2147950959"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_8_1 = {ea df 46 8f be a9 bd b9 9b f2 aa 20 1a 18 4d 38 ee}  //weight: 8, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_AHC_2147951082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.AHC!MTB"
        threat_id = "2147951082"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 f7 e9 48 01 ca 48 d1 fa 48 89 cb 48 c1 f9 3f 48 29 ca 48 85 d2 0f 8e ?? ?? ?? ?? 48 8b 44 24 68 48 89 d1 48 89 c6}  //weight: 10, accuracy: Low
        $x_20_2 = {48 8b 44 24 70 48 89 c2 48 89 d7 48 99 48 f7 f9 48 83 f8 01 75}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_PLT_2147951115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.PLT!MTB"
        threat_id = "2147951115"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {db d8 b7 d3 6d 37 d0 36 f0 9c b3 a0 6e 97 60 10 17 b2 33 98 b9 c4 43 21 37 85 6d 84 74 1d e4 10 24 f7 6e 9c bf b3 a9 cf 90 8c ac}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_PST_2147951708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.PST!MTB"
        threat_id = "2147951708"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {1b 34 c2 fe eb 37 30 58 ab 64 ec 1d a1 fa 0b e2 01 74 85 25 35 f7 26 3e e5 02 d5 66 56 2a aa 97 8e 12 fb 81 ed 85 1f 9a e2 94 1b a8 a9 94 8b 69 47 65 00 7e 7b 1e 41 4f da db 8a 0d d6 01 84 75}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_PST_2147951708_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.PST!MTB"
        threat_id = "2147951708"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {de 1b 12 93 c1 44 e2 b9 6f 5f 63 3e 8c 41 cf ba d9 e5 4f ef 34 a4 ea 87 30 d4 81 42 60 62 fa 60 e7 c5 d1 01 b0 00 16 b5 cb 18 ?? ?? ?? ?? 5b b5 2e ca 48 a5 7d 19 db be 59 52 75 7c 62 3d 6b 5f f0 78 8f 20 3d b5 24 4e 28 4c 40 26 e7 7d 25 04 e8 3c 53 64 4d b1 13 0f 76 e9 3d 05 f0 02 ba 1e 2a f1 fe 3a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_GVO_2147951757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.GVO!MTB!MTB"
        threat_id = "2147951757"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3b 4e 08 73 5e 44 8b c1 42 0f b6 44 06 10 8b d1 0f b6 54 13 10 2b d0 44 0f b6 c2 3b 4f 08 73 43 8b d1 41 33 c0 88 44 17 10 ff c1 3b e9 7f d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_GAPK_2147951932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.GAPK!MTB"
        threat_id = "2147951932"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_8_1 = {d0 1b 61 c4 8a 38 b3 12 d5 24 d5 40 eb a8 2a 88 cc 0d f0 01 9e 5d}  //weight: 8, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_IY_2147952035_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.IY!MTB"
        threat_id = "2147952035"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 89 c2 44 0f b6 44 15 ?? 44 01 c0 25 ?? ?? ?? ?? 48 63 d0 8a 4c 15 ?? 88 4d ?? 48 8b 95 ?? ?? ?? ?? 4c 8b 4d ?? 42 0f b6 04 0a 44 0f b6 45 ?? 44 31 c0 88 c1 48 8b 95 ?? ?? ?? ?? 4c 8b 4d ?? 42 88 0c 0a 48 8b 45 ?? 48 83 c0 ?? 48 89 45 ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_WAI_2147952036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.WAI!MTB"
        threat_id = "2147952036"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 01 48 63 4d ?? 48 8b 55 ?? 30 04 0a 8b 45 ?? 83 c0 ?? 89 45 ?? 8b 05 ?? ?? ?? ?? 8d 48 ?? 0f af c8 f6 c1 ?? b8 ?? ?? ?? ?? b9 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_SXA_2147952151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.SXA!MTB"
        threat_id = "2147952151"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 44 24 48 95 88 44 24 27 95 88 5c 24 26 88 54 24 25 88 4c 24 24 83 f8}  //weight: 10, accuracy: High
        $x_3_2 = {89 d7 f7 e9 c1 fa ?? 69 d2 ?? ?? ?? ?? 89 c8 29 d1 81 c1 ?? ?? ?? ?? 39 cb 0f 8d}  //weight: 3, accuracy: Low
        $x_2_3 = {89 c8 c1 e9 1f 01 c1 83 e1 fe 29 c8 40}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_GAPR_2147952313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.GAPR!MTB"
        threat_id = "2147952313"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_8_1 = {39 bd 32 6c fe de 17 33 d0 ff 61 4b 8b 41 5f 12 05 14 c4 11}  //weight: 8, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_AR_2147952486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.AR!MTB"
        threat_id = "2147952486"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {80 f1 01 89 c3 30 cb 20 c3 20 c1 08 d1 89 d8 30 c8 a8 01 ba ?? ?? ?? ?? 41 0f 45 d1 f6 c1 01 89 d0 41 0f 45 c1 f6 c3 01 0f 44 c2}  //weight: 10, accuracy: Low
        $x_8_2 = {89 ca 80 f2 01 30 c1 34 01 89 d3 20 c3 30 d0 08 d8 89 c2 30 ca a8 01 b8 ?? ?? ?? ?? 41 0f 45 c2 f6 c1 01 41 0f 44 c2}  //weight: 8, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_PGLR_2147952611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.PGLR!MTB"
        threat_id = "2147952611"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {45 89 d3 45 20 c3 45 30 d0 45 08 d8 20 d3 41 20 c9 41 08 d9 89 cb 30 d3 08 d1 80 f1 01 08 d9 80 f1 01 44 89 ca 20 ca 44 30 c9 08 d1 89 cb 80 f3 01 89 da 20 ca 30 d3 80 f2 01 08 ca 80 f2 01 08 da 44 30 c2 89 d3}  //weight: 5, accuracy: High
        $x_5_2 = {83 9f f4 bd 5f d7 72 d0 3c 58 d3 5e 82 2f 5e 04 21 22 f7 55 a8 21 21 14 95 64 53 d2 33 21 3a 71 92 03 eb 11 1b 89 06 6b 83 b3 15 24 18 a3 2b 74 e5 49 50 76 14 64 b8 bc c0 3d a2 ac}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_LummaStealer_GRR_2147953077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.GRR!MTB"
        threat_id = "2147953077"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 74 24 50 0f 11 74 24 40 48 c7 44 24 58 00 00 00 00 c7 44 24 38 58 02 00 00 c7 44 24 30 20 03 00 00 c7 44 24 28 00 00 00 80 c7 44 24 20 00 00 00 80 31 c9 48 89 fa 4c 8d 05 22 7b 08 00 41 b9 00 00 cf 00 ff 15 ad c0 08 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaStealer_RRY_2147953251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.RRY!MTB"
        threat_id = "2147953251"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {56 50 53 e8 01 00 00 00 cc 58 48 89 c3 48 ff c0 48 2d 00 10 22 00 48 2d 24 2f 0c 10 48 05 1b 2f 0c 10 80 3b cc 75 19 c6 03 00 bb 00 10 00 00 68}  //weight: 5, accuracy: High
        $x_5_2 = {41 c1 ee 02 41 81 c6 e1 b3 12 65 41 56 41 56 41 be f6 38 ef 78 44 31 74 24 08 41 5e 58 48 83 ec 08 48 89 0c 24 41 b9 ab 84 b3 33 48 c7 04 24 10}  //weight: 5, accuracy: High
        $x_5_3 = {20 2a ad 42 5e b3 65 8e 5d 20 3e 21 18 81 d0 02 9e 09 fb 0e b3 2c 62 11 d9 d5 a7 59 5a 80 f0 b5 61 46 94 1a 00 12 6b 85 9b d2 89 69 65 f4 29 18}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_LummaStealer_RRX_2147953252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealer.RRX!MTB"
        threat_id = "2147953252"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {50 e7 3f 41 81 ee f7 92 f7 57 41 f7 d6 41 81 e6 a4 d8 b6 7b 41 ff ce 41 f7 d6 41 81 ee 26 7c a4 bc 44 01 f3 41 31 c6 89 d8}  //weight: 5, accuracy: High
        $x_5_2 = {81 c2 10 18 75 3b 81 c6 3d 9d 31 9a 89 f0 52 ba e0 8e e5 45 29 d6 5a 81 ee 2e 25 76 6a 01 d6 81 c6 2e 25 76 6a 81 c6 e0 8e e5 45}  //weight: 5, accuracy: High
        $x_5_3 = {81 c2 96 ec 66 39 81 ea 00 00 ff 4f 31 d2 be 80 94 67 3d 81 f6 be 69 89 3a 29 f2 01 c6 31 d6 29 da 81 c2 3e fd ee 07}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

