rule Trojan_Win64_DCRat_RDA_2147844564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DCRat.RDA!MTB"
        threat_id = "2147844564"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//a0791030.xsph.ru/exta.exe" ascii //weight: 1
        $x_1_2 = "start C:\\ProgramData\\exta.exe" ascii //weight: 1
        $x_1_3 = "Create by constant#1900" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DCRat_SPQS_2147845023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DCRat.SPQS!MTB"
        threat_id = "2147845023"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://free1459.host.od.ua/RustCheatCheck.exe" wide //weight: 1
        $x_1_2 = "RustCheatCheck.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DCRat_A_2147849418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DCRat.A!MTB"
        threat_id = "2147849418"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 ff c7 48 63 05 ?? ?? 09 00 48 83 c6 ?? 48 39 c7 7c 09 00 89 ?? 41 ff ?? 48 83 c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DCRat_B_2147849437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DCRat.B!MTB"
        threat_id = "2147849437"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff d6 85 c0 75 ?? 48 83 c3 ?? 48 83 c7 ?? 48 81 ff ?? ?? ?? ?? 75 07 00 4a 8b 0c 27 48 89 da}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DCRat_C_2147849518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DCRat.C!MTB"
        threat_id = "2147849518"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4c 89 e2 49 89 d8 ff ?? 3d ?? ?? ?? ?? 74 ?? 48 83 c3 ?? 48 83 c6 ?? 48 81 fe ?? ?? ?? ?? 75 04 00 4a 8b 0c 3e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DCRat_D_2147850305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DCRat.D!MTB"
        threat_id = "2147850305"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 89 c1 8b 45 ?? 48 0f be 11 48 8d 0d ?? ?? ?? ?? 0f be 0c 11 c1 f9 ?? 83 e1 ?? 09 c8 88}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DCRat_E_2147850686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DCRat.E!MTB"
        threat_id = "2147850686"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4c 8b 17 4f 0f be 5c 8a ?? 45 0f b6 1c 0b 41 c0 e3 ?? 4f 0f be 54 8a ?? 45 0f b6 14 0a 41 80 e2 ?? 45 08 da 48 83 7d f8 ?? 4d 89 c3 0f 82}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DCRat_F_2147850687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DCRat.F!MTB"
        threat_id = "2147850687"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4c 8b 13 48 83 ?? 01 49 0f be 4c 02 01 4d 0f be 14 02 41 0f be 0c ?? 47 0f be 14 ?? c1 f9 04 41 c1 e2 02 83 e1 03 44 09 d1 4c 8b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DCRat_G_2147850688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DCRat.G!MTB"
        threat_id = "2147850688"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 00 0f be c0 48 98 48 8d 15 ?? ?? ?? ?? 0f b6 04 10 0f be c0 c1 e0 02 83 e0 ?? 89 c6 48 8b 45 e8 48 c1 e0 02 48 83 c0 01 48 89 c2 48 8b 4d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DCRat_H_2147923750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DCRat.H!MTB"
        threat_id = "2147923750"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 eb 03 d3 c1 fa ?? 8b c2 c1 e8 1f 03 d0 b8 ?? ?? ?? ?? 2a c2 0f be c0 6b c8 ?? 02 cb ff c3 41 30 48 ff 83 fb}  //weight: 2, accuracy: Low
        $x_4_2 = {41 f7 e0 41 8b c0 2b c2 d1 ?? 03 c2 c1 e8 ?? 0f be c0 6b c8 ?? 41 0f b6 c0 41 ff c0 2a c1 04 39 41 30 41 ff 41 83 f8}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DCRat_PD_2147925359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DCRat.PD!MTB"
        threat_id = "2147925359"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Go build ID: " ascii //weight: 1
        $x_1_2 = "portgetaddrinfowtransmitfile" ascii //weight: 1
        $x_1_3 = "net/http.fakeLocker,sync.Locker" ascii //weight: 1
        $x_3_4 = "github.com/MrBrounr/main/raw/main/naker.exe" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DCRat_RPA_2147936606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DCRat.RPA!MTB"
        threat_id = "2147936606"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "110"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "YHotZpSNVVz9iLVifj9gGjLu8" ascii //weight: 100
        $x_10_2 = {5f 43 6f 72 45 00 78 65 4d 61 69 6e 00 6d 00 73 63 6f 72 65 65 2e 64 43 6c}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DCRat_ETL_2147944790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DCRat.ETL!MTB"
        threat_id = "2147944790"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b8 a1 a0 a0 a0 41 f7 e0 c1 ea 05 0f be c2 6b c8 33 41 0f b6 c0 2a c1 04 32 41 30 01 41 ff c0 4d 8d 49 01 41 83 f8 10 7c d7}  //weight: 2, accuracy: High
        $x_1_2 = "Loader.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DCRat_GVC_2147954272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DCRat.GVC!MTB"
        threat_id = "2147954272"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b0 06 bd c2 ef d9 fe 50 21 51 fa 29 c9 4c 85 15 00 19 1b 04 3d d9 48 c7 7d 30 64 e8 47 7a 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DCRat_YAE_2147954700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DCRat.YAE!MTB"
        threat_id = "2147954700"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 0f be 0c 01 49 ff c0 03 ca 69 d1 ?? ?? ?? ?? 8b ca c1 e9 06 33 d1 4c 3b c0 75 e4 8d 04 d2 8b c8 c1 e9 0b 33 c8}  //weight: 1, accuracy: Low
        $x_1_2 = "OnlyNoConsole\\svc.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DCRat_YAF_2147954701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DCRat.YAF!MTB"
        threat_id = "2147954701"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "https://tmpfiles.org/" ascii //weight: 2
        $x_1_2 = "Add-MpPreference -ExclusionPath" ascii //weight: 1
        $x_1_3 = "powershell -Command \"Invoke-WebRequest -Uri" ascii //weight: 1
        $x_1_4 = {53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 27 43 3a 5c [0-48] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DCRat_MK_2147954935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DCRat.MK!MTB"
        threat_id = "2147954935"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {f2 48 0f 2a d1 66 0f 6e c8 f3 0f e6 c9 f3 0f e6 c0 f2 0f 58 c0 f2 0f 5c c8 f2 0f 59 ca f2 0f 11 4d b7}  //weight: 20, accuracy: High
        $x_15_2 = "Curre360leakfixer.exe" ascii //weight: 15
        $x_3_3 = "%s\\ok_%ld.stml" ascii //weight: 3
        $x_2_4 = "%s\\ok_%ld.txt" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DCRat_CR_2147958570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DCRat.CR!MTB"
        threat_id = "2147958570"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d 34 5b 48 8b 34 f2 48 89 34 d8 48 ff c3 48 39 cb 7c ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

