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
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {74 29 8b 05 ?? ?? ?? ?? 65 48 8b 0c 25 ?? ?? ?? ?? 48 8b 04 c1 4c 8b 80 ?? ?? ?? ?? 48 8b 0d 46 b0 2e 00 31 d2}  //weight: 5, accuracy: Low
        $x_1_2 = "maninternmentsrijibmaninternment" ascii //weight: 1
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
        $x_5_1 = {48 63 44 24 ?? 48 8b 4c 24 20 69 04 81 95 e9 d1 5b 89 c1 c1 e9 ?? 31 c1 69 c1 95 e9 d1 5b 69 5c 24 ?? 95 e9 d1 5b 31 c3 8b 6c 24 ?? 83 c5 ?? 41 ba ?? ?? ?? ?? 41 81 fa ?? ?? ?? ?? 0f 8f ?? ?? ?? ?? e9}  //weight: 5, accuracy: Low
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

