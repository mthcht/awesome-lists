rule Trojan_Win64_AbuseCommMain_A_2147824255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.A"
        threat_id = "2147824255"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:3085B89A0C515D2FB124D645906F5D3DA5CB97CEBEA975959AE4F95302A04E1D" wide //weight: 1
        $x_1_2 = {33 30 38 35 42 38 39 41 30 43 35 31 35 44 32 46 42 31 32 34 44 36 34 35 39 30 36 46 35 44 33 44 41 35 43 42 39 37 43 45 42 45 41 39 37 35 39 35 39 41 45 34 46 39 35 33 30 32 41 30 34 45 31 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {33 30 38 35 42 38 39 41 30 43 35 31 35 44 32 46 42 31 32 34 44 36 34 35 39 30 36 46 35 44 33 44 41 35 43 42 39 37 43 45 42 45 41 39 37 35 39 35 39 41 45 34 46 39 35 33 30 32 41 30 34 45 31 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\3085B89A0C515D2FB124D645906F5D3DA5CB97CEBEA975959AE4F95302A04E1D.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_B_2147824926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.B"
        threat_id = "2147824926"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:8BEDC411012A33BA34F49130D0F186993C6A32DAD8976F6A5D82C1ED23054C05" wide //weight: 1
        $x_1_2 = {38 42 45 44 43 34 31 31 30 31 32 41 33 33 42 41 33 34 46 34 39 31 33 30 44 30 46 31 38 36 39 39 33 43 36 41 33 32 44 41 44 38 39 37 36 46 36 41 35 44 38 32 43 31 45 44 32 33 30 35 34 43 30 35 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {38 42 45 44 43 34 31 31 30 31 32 41 33 33 42 41 33 34 46 34 39 31 33 30 44 30 46 31 38 36 39 39 33 43 36 41 33 32 44 41 44 38 39 37 36 46 36 41 35 44 38 32 43 31 45 44 32 33 30 35 34 43 30 35 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\8BEDC411012A33BA34F49130D0F186993C6A32DAD8976F6A5D82C1ED23054C05.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_C_2147824930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.C"
        threat_id = "2147824930"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:3728E933284CE638D06FCF1CBE921096E102508BD370D6D23137D3271EE57338" wide //weight: 1
        $x_1_2 = {33 37 32 38 45 39 33 33 32 38 34 43 45 36 33 38 44 30 36 46 43 46 31 43 42 45 39 32 31 30 39 36 45 31 30 32 35 30 38 42 44 33 37 30 44 36 44 32 33 31 33 37 44 33 32 37 31 45 45 35 37 33 33 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {33 37 32 38 45 39 33 33 32 38 34 43 45 36 33 38 44 30 36 46 43 46 31 43 42 45 39 32 31 30 39 36 45 31 30 32 35 30 38 42 44 33 37 30 44 36 44 32 33 31 33 37 44 33 32 37 31 45 45 35 37 33 33 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\3728E933284CE638D06FCF1CBE921096E102508BD370D6D23137D3271EE57338.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_D_2147824934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.D"
        threat_id = "2147824934"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:81B2B719AB9BDDCE9116776FA01956C2D4BB8A7CA5464592593F9A25DA1F9117" wide //weight: 1
        $x_1_2 = {38 31 42 32 42 37 31 39 41 42 39 42 44 44 43 45 39 31 31 36 37 37 36 46 41 30 31 39 35 36 43 32 44 34 42 42 38 41 37 43 41 35 34 36 34 35 39 32 35 39 33 46 39 41 32 35 44 41 31 46 39 31 31 37 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {38 31 42 32 42 37 31 39 41 42 39 42 44 44 43 45 39 31 31 36 37 37 36 46 41 30 31 39 35 36 43 32 44 34 42 42 38 41 37 43 41 35 34 36 34 35 39 32 35 39 33 46 39 41 32 35 44 41 31 46 39 31 31 37 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\81B2B719AB9BDDCE9116776FA01956C2D4BB8A7CA5464592593F9A25DA1F9117.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_E_2147824938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.E"
        threat_id = "2147824938"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:6F548F217897AA4140FB4C514C8187F2FFDBA3CAFC83795DEE2FBCA369E68900" wide //weight: 1
        $x_1_2 = {36 46 35 34 38 46 32 31 37 38 39 37 41 41 34 31 34 30 46 42 34 43 35 31 34 43 38 31 38 37 46 32 46 46 44 42 41 33 43 41 46 43 38 33 37 39 35 44 45 45 32 46 42 43 41 33 36 39 45 36 38 39 30 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {36 46 35 34 38 46 32 31 37 38 39 37 41 41 34 31 34 30 46 42 34 43 35 31 34 43 38 31 38 37 46 32 46 46 44 42 41 33 43 41 46 43 38 33 37 39 35 44 45 45 32 46 42 43 41 33 36 39 45 36 38 39 30 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\6F548F217897AA4140FB4C514C8187F2FFDBA3CAFC83795DEE2FBCA369E68900.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_F_2147826169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.F"
        threat_id = "2147826169"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:35F36AF07A7FD5232EB10F69DB4A6FB4AFA54A88357F0CD23816A6756FAA6F1E" wide //weight: 1
        $x_1_2 = {33 35 46 33 36 41 46 30 37 41 37 46 44 35 32 33 32 45 42 31 30 46 36 39 44 42 34 41 36 46 42 34 41 46 41 35 34 41 38 38 33 35 37 46 30 43 44 32 33 38 31 36 41 36 37 35 36 46 41 41 36 46 31 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {33 35 46 33 36 41 46 30 37 41 37 46 44 35 32 33 32 45 42 31 30 46 36 39 44 42 34 41 36 46 42 34 41 46 41 35 34 41 38 38 33 35 37 46 30 43 44 32 33 38 31 36 41 36 37 35 36 46 41 41 36 46 31 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\35F36AF07A7FD5232EB10F69DB4A6FB4AFA54A88357F0CD23816A6756FAA6F1E.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_G_2147826173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.G"
        threat_id = "2147826173"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:6C5AD4057E594E090E0C987B3089F74335DA75F04B7403E0575663C261349569" wide //weight: 1
        $x_1_2 = {36 43 35 41 44 34 30 35 37 45 35 39 34 45 30 39 30 45 30 43 39 38 37 42 33 30 38 39 46 37 34 33 33 35 44 41 37 35 46 30 34 42 37 34 30 33 45 30 35 37 35 36 36 33 43 32 36 31 33 34 39 35 36 39 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {36 43 35 41 44 34 30 35 37 45 35 39 34 45 30 39 30 45 30 43 39 38 37 42 33 30 38 39 46 37 34 33 33 35 44 41 37 35 46 30 34 42 37 34 30 33 45 30 35 37 35 36 36 33 43 32 36 31 33 34 39 35 36 39 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\6C5AD4057E594E090E0C987B3089F74335DA75F04B7403E0575663C261349569.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_H_2147826982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.H"
        threat_id = "2147826982"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:0FF26770BFAEAD95194506E6970CC1C395B04159038D785DE316F05CE6DE6732" wide //weight: 1
        $x_1_2 = {30 46 46 32 36 37 37 30 42 46 41 45 41 44 39 35 31 39 34 35 30 36 45 36 39 37 30 43 43 31 43 33 39 35 42 30 34 31 35 39 30 33 38 44 37 38 35 44 45 33 31 36 46 30 35 43 45 36 44 45 36 37 33 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {30 46 46 32 36 37 37 30 42 46 41 45 41 44 39 35 31 39 34 35 30 36 45 36 39 37 30 43 43 31 43 33 39 35 42 30 34 31 35 39 30 33 38 44 37 38 35 44 45 33 31 36 46 30 35 43 45 36 44 45 36 37 33 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\0FF26770BFAEAD95194506E6970CC1C395B04159038D785DE316F05CE6DE6732.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_I_2147826986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.I"
        threat_id = "2147826986"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:BBA99964ECC6CA4A8B6460FB0CB45AD8781AC01D94F6F6DBF9B9D1202BAF1822" wide //weight: 1
        $x_1_2 = {42 42 41 39 39 39 36 34 45 43 43 36 43 41 34 41 38 42 36 34 36 30 46 42 30 43 42 34 35 41 44 38 37 38 31 41 43 30 31 44 39 34 46 36 46 36 44 42 46 39 42 39 44 31 32 30 32 42 41 46 31 38 32 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {42 42 41 39 39 39 36 34 45 43 43 36 43 41 34 41 38 42 36 34 36 30 46 42 30 43 42 34 35 41 44 38 37 38 31 41 43 30 31 44 39 34 46 36 46 36 44 42 46 39 42 39 44 31 32 30 32 42 41 46 31 38 32 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\BBA99964ECC6CA4A8B6460FB0CB45AD8781AC01D94F6F6DBF9B9D1202BAF1822.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_J_2147827311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.J"
        threat_id = "2147827311"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:F17A21223580DBB02D4FA592B5568B09594B7A90BA21C31534BF2EF7D3082C29" wide //weight: 1
        $x_1_2 = {46 31 37 41 32 31 32 32 33 35 38 30 44 42 42 30 32 44 34 46 41 35 39 32 42 35 35 36 38 42 30 39 35 39 34 42 37 41 39 30 42 41 32 31 43 33 31 35 33 34 42 46 32 45 46 37 44 33 30 38 32 43 32 39 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {46 31 37 41 32 31 32 32 33 35 38 30 44 42 42 30 32 44 34 46 41 35 39 32 42 35 35 36 38 42 30 39 35 39 34 42 37 41 39 30 42 41 32 31 43 33 31 35 33 34 42 46 32 45 46 37 44 33 30 38 32 43 32 39 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\F17A21223580DBB02D4FA592B5568B09594B7A90BA21C31534BF2EF7D3082C29.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_K_2147827315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.K"
        threat_id = "2147827315"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:10D20B109E895D2FBC70F11E9A775825E9397B0B89FE00FDD96BA8158F8A542A" wide //weight: 1
        $x_1_2 = {31 30 44 32 30 42 31 30 39 45 38 39 35 44 32 46 42 43 37 30 46 31 31 45 39 41 37 37 35 38 32 35 45 39 33 39 37 42 30 42 38 39 46 45 30 30 46 44 44 39 36 42 41 38 31 35 38 46 38 41 35 34 32 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {31 30 44 32 30 42 31 30 39 45 38 39 35 44 32 46 42 43 37 30 46 31 31 45 39 41 37 37 35 38 32 35 45 39 33 39 37 42 30 42 38 39 46 45 30 30 46 44 44 39 36 42 41 38 31 35 38 46 38 41 35 34 32 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\10D20B109E895D2FBC70F11E9A775825E9397B0B89FE00FDD96BA8158F8A542A.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_L_2147827319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.L"
        threat_id = "2147827319"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:891176DC3A1523F997D84069748364BD68505DA42153B1D1BF784AFB9DADBE51" wide //weight: 1
        $x_1_2 = {38 39 31 31 37 36 44 43 33 41 31 35 32 33 46 39 39 37 44 38 34 30 36 39 37 34 38 33 36 34 42 44 36 38 35 30 35 44 41 34 32 31 35 33 42 31 44 31 42 46 37 38 34 41 46 42 39 44 41 44 42 45 35 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {38 39 31 31 37 36 44 43 33 41 31 35 32 33 46 39 39 37 44 38 34 30 36 39 37 34 38 33 36 34 42 44 36 38 35 30 35 44 41 34 32 31 35 33 42 31 44 31 42 46 37 38 34 41 46 42 39 44 41 44 42 45 35 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\891176DC3A1523F997D84069748364BD68505DA42153B1D1BF784AFB9DADBE51.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_M_2147827323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.M"
        threat_id = "2147827323"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:D5D9827F7186A50EABC1FBFD3DE8101792F187C584DA9D3D9DEAADBE23DCB16E" wide //weight: 1
        $x_1_2 = {44 35 44 39 38 32 37 46 37 31 38 36 41 35 30 45 41 42 43 31 46 42 46 44 33 44 45 38 31 30 31 37 39 32 46 31 38 37 43 35 38 34 44 41 39 44 33 44 39 44 45 41 41 44 42 45 32 33 44 43 42 31 36 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {44 35 44 39 38 32 37 46 37 31 38 36 41 35 30 45 41 42 43 31 46 42 46 44 33 44 45 38 31 30 31 37 39 32 46 31 38 37 43 35 38 34 44 41 39 44 33 44 39 44 45 41 41 44 42 45 32 33 44 43 42 31 36 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\D5D9827F7186A50EABC1FBFD3DE8101792F187C584DA9D3D9DEAADBE23DCB16E.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_N_2147827327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.N"
        threat_id = "2147827327"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:070AD41653BADCD8CFE9EEBDC363107BA87DB5C3E56F2EE8A261F8B70EF61F0A" wide //weight: 1
        $x_1_2 = {30 37 30 41 44 34 31 36 35 33 42 41 44 43 44 38 43 46 45 39 45 45 42 44 43 33 36 33 31 30 37 42 41 38 37 44 42 35 43 33 45 35 36 46 32 45 45 38 41 32 36 31 46 38 42 37 30 45 46 36 31 46 30 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {30 37 30 41 44 34 31 36 35 33 42 41 44 43 44 38 43 46 45 39 45 45 42 44 43 33 36 33 31 30 37 42 41 38 37 44 42 35 43 33 45 35 36 46 32 45 45 38 41 32 36 31 46 38 42 37 30 45 46 36 31 46 30 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\070AD41653BADCD8CFE9EEBDC363107BA87DB5C3E56F2EE8A261F8B70EF61F0A.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_O_2147827331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.O"
        threat_id = "2147827331"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:885800AB83209EB47A9FC6C667224DB9B0DC02EEE1105229AC22E4F1D6A2125E" wide //weight: 1
        $x_1_2 = {38 38 35 38 30 30 41 42 38 33 32 30 39 45 42 34 37 41 39 46 43 36 43 36 36 37 32 32 34 44 42 39 42 30 44 43 30 32 45 45 45 31 31 30 35 32 32 39 41 43 32 32 45 34 46 31 44 36 41 32 31 32 35 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {38 38 35 38 30 30 41 42 38 33 32 30 39 45 42 34 37 41 39 46 43 36 43 36 36 37 32 32 34 44 42 39 42 30 44 43 30 32 45 45 45 31 31 30 35 32 32 39 41 43 32 32 45 34 46 31 44 36 41 32 31 32 35 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\885800AB83209EB47A9FC6C667224DB9B0DC02EEE1105229AC22E4F1D6A2125E.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_P_2147827979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.P"
        threat_id = "2147827979"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:AB4FEBA9CABBD9E98CBF6745592B0E1C34F91492FD8D02AD802F92C893F49B20" wide //weight: 1
        $x_1_2 = {41 42 34 46 45 42 41 39 43 41 42 42 44 39 45 39 38 43 42 46 36 37 34 35 35 39 32 42 30 45 31 43 33 34 46 39 31 34 39 32 46 44 38 44 30 32 41 44 38 30 32 46 39 32 43 38 39 33 46 34 39 42 32 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {41 42 34 46 45 42 41 39 43 41 42 42 44 39 45 39 38 43 42 46 36 37 34 35 35 39 32 42 30 45 31 43 33 34 46 39 31 34 39 32 46 44 38 44 30 32 41 44 38 30 32 46 39 32 43 38 39 33 46 34 39 42 32 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\AB4FEBA9CABBD9E98CBF6745592B0E1C34F91492FD8D02AD802F92C893F49B20.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_Q_2147829190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.Q"
        threat_id = "2147829190"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:ABF25D000C5375AA30743D32E30C60B603048117B99CFF0C8ECC1EB53F9C7958" wide //weight: 1
        $x_1_2 = {41 42 46 32 35 44 30 30 30 43 35 33 37 35 41 41 33 30 37 34 33 44 33 32 45 33 30 43 36 30 42 36 30 33 30 34 38 31 31 37 42 39 39 43 46 46 30 43 38 45 43 43 31 45 42 35 33 46 39 43 37 39 35 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {41 42 46 32 35 44 30 30 30 43 35 33 37 35 41 41 33 30 37 34 33 44 33 32 45 33 30 43 36 30 42 36 30 33 30 34 38 31 31 37 42 39 39 43 46 46 30 43 38 45 43 43 31 45 42 35 33 46 39 43 37 39 35 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\ABF25D000C5375AA30743D32E30C60B603048117B99CFF0C8ECC1EB53F9C7958.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_R_2147829304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.R"
        threat_id = "2147829304"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:4F152368FB89FA84E292D30C007046511FE12FE35D4C0AEA74A15FB0E5A90848" wide //weight: 1
        $x_1_2 = {34 46 31 35 32 33 36 38 46 42 38 39 46 41 38 34 45 32 39 32 44 33 30 43 30 30 37 30 34 36 35 31 31 46 45 31 32 46 45 33 35 44 34 43 30 41 45 41 37 34 41 31 35 46 42 30 45 35 41 39 30 38 34 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {34 46 31 35 32 33 36 38 46 42 38 39 46 41 38 34 45 32 39 32 44 33 30 43 30 30 37 30 34 36 35 31 31 46 45 31 32 46 45 33 35 44 34 43 30 41 45 41 37 34 41 31 35 46 42 30 45 35 41 39 30 38 34 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\4F152368FB89FA84E292D30C007046511FE12FE35D4C0AEA74A15FB0E5A90848.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_S_2147829308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.S"
        threat_id = "2147829308"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:671263E7BC06103C77146A5ABB802A63F53A42B4C4766329A5F04D2660C99A36" wide //weight: 1
        $x_1_2 = {36 37 31 32 36 33 45 37 42 43 30 36 31 30 33 43 37 37 31 34 36 41 35 41 42 42 38 30 32 41 36 33 46 35 33 41 34 32 42 34 43 34 37 36 36 33 32 39 41 35 46 30 34 44 32 36 36 30 43 39 39 41 33 36 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {36 37 31 32 36 33 45 37 42 43 30 36 31 30 33 43 37 37 31 34 36 41 35 41 42 42 38 30 32 41 36 33 46 35 33 41 34 32 42 34 43 34 37 36 36 33 32 39 41 35 46 30 34 44 32 36 36 30 43 39 39 41 33 36 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\671263E7BC06103C77146A5ABB802A63F53A42B4C4766329A5F04D2660C99A36.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_T_2147829450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.T"
        threat_id = "2147829450"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:A2DCDE8AAC5AB15F552621CF24A44A708EDFD0C89E22AE77087FA1E2F4FA057A" wide //weight: 1
        $x_1_2 = {41 32 44 43 44 45 38 41 41 43 35 41 42 31 35 46 35 35 32 36 32 31 43 46 32 34 41 34 34 41 37 30 38 45 44 46 44 30 43 38 39 45 32 32 41 45 37 37 30 38 37 46 41 31 45 32 46 34 46 41 30 35 37 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {41 32 44 43 44 45 38 41 41 43 35 41 42 31 35 46 35 35 32 36 32 31 43 46 32 34 41 34 34 41 37 30 38 45 44 46 44 30 43 38 39 45 32 32 41 45 37 37 30 38 37 46 41 31 45 32 46 34 46 41 30 35 37 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\A2DCDE8AAC5AB15F552621CF24A44A708EDFD0C89E22AE77087FA1E2F4FA057A.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_U_2147829454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.U"
        threat_id = "2147829454"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:AEBC11812927786A9A05D3BC5849359BA58601586F4FF356E0CE7EDE218DA002" wide //weight: 1
        $x_1_2 = {41 45 42 43 31 31 38 31 32 39 32 37 37 38 36 41 39 41 30 35 44 33 42 43 35 38 34 39 33 35 39 42 41 35 38 36 30 31 35 38 36 46 34 46 46 33 35 36 45 30 43 45 37 45 44 45 32 31 38 44 41 30 30 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {41 45 42 43 31 31 38 31 32 39 32 37 37 38 36 41 39 41 30 35 44 33 42 43 35 38 34 39 33 35 39 42 41 35 38 36 30 31 35 38 36 46 34 46 46 33 35 36 45 30 43 45 37 45 44 45 32 31 38 44 41 30 30 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\AEBC11812927786A9A05D3BC5849359BA58601586F4FF356E0CE7EDE218DA002.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_V_2147830246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.V"
        threat_id = "2147830246"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:E906C710E15BCB045AD06338132ADB4591BFCE0107B66CFA64DD26A24931DE60" wide //weight: 1
        $x_1_2 = {45 39 30 36 43 37 31 30 45 31 35 42 43 42 30 34 35 41 44 30 36 33 33 38 31 33 32 41 44 42 34 35 39 31 42 46 43 45 30 31 30 37 42 36 36 43 46 41 36 34 44 44 32 36 41 32 34 39 33 31 44 45 36 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {45 39 30 36 43 37 31 30 45 31 35 42 43 42 30 34 35 41 44 30 36 33 33 38 31 33 32 41 44 42 34 35 39 31 42 46 43 45 30 31 30 37 42 36 36 43 46 41 36 34 44 44 32 36 41 32 34 39 33 31 44 45 36 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\E906C710E15BCB045AD06338132ADB4591BFCE0107B66CFA64DD26A24931DE60.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_W_2147830348_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.W"
        threat_id = "2147830348"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:88245BB83F14FD2EC517E3B09E56F968C1C4CD8162D5E534AD09438712E8D85D" wide //weight: 1
        $x_1_2 = {38 38 32 34 35 42 42 38 33 46 31 34 46 44 32 45 43 35 31 37 45 33 42 30 39 45 35 36 46 39 36 38 43 31 43 34 43 44 38 31 36 32 44 35 45 35 33 34 41 44 30 39 34 33 38 37 31 32 45 38 44 38 35 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {38 38 32 34 35 42 42 38 33 46 31 34 46 44 32 45 43 35 31 37 45 33 42 30 39 45 35 36 46 39 36 38 43 31 43 34 43 44 38 31 36 32 44 35 45 35 33 34 41 44 30 39 34 33 38 37 31 32 45 38 44 38 35 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\88245BB83F14FD2EC517E3B09E56F968C1C4CD8162D5E534AD09438712E8D85D.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_X_2147830544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.X"
        threat_id = "2147830544"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:D3404141459BC7206CC4AFEC16A3403F262C0937A732C12644E7CA97F0615201" wide //weight: 1
        $x_1_2 = {44 33 34 30 34 31 34 31 34 35 39 42 43 37 32 30 36 43 43 34 41 46 45 43 31 36 41 33 34 30 33 46 32 36 32 43 30 39 33 37 41 37 33 32 43 31 32 36 34 34 45 37 43 41 39 37 46 30 36 31 35 32 30 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {44 33 34 30 34 31 34 31 34 35 39 42 43 37 32 30 36 43 43 34 41 46 45 43 31 36 41 33 34 30 33 46 32 36 32 43 30 39 33 37 41 37 33 32 43 31 32 36 34 34 45 37 43 41 39 37 46 30 36 31 35 32 30 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\D3404141459BC7206CC4AFEC16A3403F262C0937A732C12644E7CA97F0615201.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_Y_2147831035_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.Y"
        threat_id = "2147831035"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:E4769B1DEF6167C65799E7FA724004E97F6AC5F7C65F9DFF05F6674C5BAA3E42" wide //weight: 1
        $x_1_2 = {45 34 37 36 39 42 31 44 45 46 36 31 36 37 43 36 35 37 39 39 45 37 46 41 37 32 34 30 30 34 45 39 37 46 36 41 43 35 46 37 43 36 35 46 39 44 46 46 30 35 46 36 36 37 34 43 35 42 41 41 33 45 34 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {45 34 37 36 39 42 31 44 45 46 36 31 36 37 43 36 35 37 39 39 45 37 46 41 37 32 34 30 30 34 45 39 37 46 36 41 43 35 46 37 43 36 35 46 39 44 46 46 30 35 46 36 36 37 34 43 35 42 41 41 33 45 34 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\E4769B1DEF6167C65799E7FA724004E97F6AC5F7C65F9DFF05F6674C5BAA3E42.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_Z_2147831039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.Z"
        threat_id = "2147831039"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:C135F524E4C75FA00B5620F4286FFE7906E459673A64800EF20D944863946E1F" wide //weight: 1
        $x_1_2 = {43 31 33 35 46 35 32 34 45 34 43 37 35 46 41 30 30 42 35 36 32 30 46 34 32 38 36 46 46 45 37 39 30 36 45 34 35 39 36 37 33 41 36 34 38 30 30 45 46 32 30 44 39 34 34 38 36 33 39 34 36 45 31 46 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {43 31 33 35 46 35 32 34 45 34 43 37 35 46 41 30 30 42 35 36 32 30 46 34 32 38 36 46 46 45 37 39 30 36 45 34 35 39 36 37 33 41 36 34 38 30 30 45 46 32 30 44 39 34 34 38 36 33 39 34 36 45 31 46 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\C135F524E4C75FA00B5620F4286FFE7906E459673A64800EF20D944863946E1F.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_AA_2147831043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.AA"
        threat_id = "2147831043"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:007A21A27C39CC64D9AB066A9A71B7B0BE575EE9D287189235BB1F376438150B" wide //weight: 1
        $x_1_2 = {30 30 37 41 32 31 41 32 37 43 33 39 43 43 36 34 44 39 41 42 30 36 36 41 39 41 37 31 42 37 42 30 42 45 35 37 35 45 45 39 44 32 38 37 31 38 39 32 33 35 42 42 31 46 33 37 36 34 33 38 31 35 30 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {30 30 37 41 32 31 41 32 37 43 33 39 43 43 36 34 44 39 41 42 30 36 36 41 39 41 37 31 42 37 42 30 42 45 35 37 35 45 45 39 44 32 38 37 31 38 39 32 33 35 42 42 31 46 33 37 36 34 33 38 31 35 30 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\007A21A27C39CC64D9AB066A9A71B7B0BE575EE9D287189235BB1F376438150B.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_AB_2147831047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.AB"
        threat_id = "2147831047"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:0EDC46A1C7F449FE1B056633F33A665E070968FE708845B9CC7F0EADCC49921D" wide //weight: 1
        $x_1_2 = {30 45 44 43 34 36 41 31 43 37 46 34 34 39 46 45 31 42 30 35 36 36 33 33 46 33 33 41 36 36 35 45 30 37 30 39 36 38 46 45 37 30 38 38 34 35 42 39 43 43 37 46 30 45 41 44 43 43 34 39 39 32 31 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {30 45 44 43 34 36 41 31 43 37 46 34 34 39 46 45 31 42 30 35 36 36 33 33 46 33 33 41 36 36 35 45 30 37 30 39 36 38 46 45 37 30 38 38 34 35 42 39 43 43 37 46 30 45 41 44 43 43 34 39 39 32 31 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\0EDC46A1C7F449FE1B056633F33A665E070968FE708845B9CC7F0EADCC49921D.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_AC_2147831051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.AC"
        threat_id = "2147831051"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:899D28D0C43BBF7FE3E4FE5B0CB80914BE4ADA8780A04AFCF6249A95ABA10170" wide //weight: 1
        $x_1_2 = {38 39 39 44 32 38 44 30 43 34 33 42 42 46 37 46 45 33 45 34 46 45 35 42 30 43 42 38 30 39 31 34 42 45 34 41 44 41 38 37 38 30 41 30 34 41 46 43 46 36 32 34 39 41 39 35 41 42 41 31 30 31 37 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {38 39 39 44 32 38 44 30 43 34 33 42 42 46 37 46 45 33 45 34 46 45 35 42 30 43 42 38 30 39 31 34 42 45 34 41 44 41 38 37 38 30 41 30 34 41 46 43 46 36 32 34 39 41 39 35 41 42 41 31 30 31 37 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\899D28D0C43BBF7FE3E4FE5B0CB80914BE4ADA8780A04AFCF6249A95ABA10170.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_AD_2147831055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.AD"
        threat_id = "2147831055"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:3488458145EB62D7D3947E3811234F4663D9B5AEEF6584AB08A2099A7F946664" wide //weight: 1
        $x_1_2 = {33 34 38 38 34 35 38 31 34 35 45 42 36 32 44 37 44 33 39 34 37 45 33 38 31 31 32 33 34 46 34 36 36 33 44 39 42 35 41 45 45 46 36 35 38 34 41 42 30 38 41 32 30 39 39 41 37 46 39 34 36 36 36 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {33 34 38 38 34 35 38 31 34 35 45 42 36 32 44 37 44 33 39 34 37 45 33 38 31 31 32 33 34 46 34 36 36 33 44 39 42 35 41 45 45 46 36 35 38 34 41 42 30 38 41 32 30 39 39 41 37 46 39 34 36 36 36 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\3488458145EB62D7D3947E3811234F4663D9B5AEEF6584AB08A2099A7F946664.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_AE_2147831059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.AE"
        threat_id = "2147831059"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:78DB22E30C48561EF8B63AFF7702B237A4797017EBC3630853CF6F11F8706A3A" wide //weight: 1
        $x_1_2 = {37 38 44 42 32 32 45 33 30 43 34 38 35 36 31 45 46 38 42 36 33 41 46 46 37 37 30 32 42 32 33 37 41 34 37 39 37 30 31 37 45 42 43 33 36 33 30 38 35 33 43 46 36 46 31 31 46 38 37 30 36 41 33 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {37 38 44 42 32 32 45 33 30 43 34 38 35 36 31 45 46 38 42 36 33 41 46 46 37 37 30 32 42 32 33 37 41 34 37 39 37 30 31 37 45 42 43 33 36 33 30 38 35 33 43 46 36 46 31 31 46 38 37 30 36 41 33 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\78DB22E30C48561EF8B63AFF7702B237A4797017EBC3630853CF6F11F8706A3A.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_AF_2147831063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.AF"
        threat_id = "2147831063"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:37790E2D198DFD20C9D2887D4EF7C3E2951BB84248D192689B64DCCA3C8BD808" wide //weight: 1
        $x_1_2 = {33 37 37 39 30 45 32 44 31 39 38 44 46 44 32 30 43 39 44 32 38 38 37 44 34 45 46 37 43 33 45 32 39 35 31 42 42 38 34 32 34 38 44 31 39 32 36 38 39 42 36 34 44 43 43 41 33 43 38 42 44 38 30 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {33 37 37 39 30 45 32 44 31 39 38 44 46 44 32 30 43 39 44 32 38 38 37 44 34 45 46 37 43 33 45 32 39 35 31 42 42 38 34 32 34 38 44 31 39 32 36 38 39 42 36 34 44 43 43 41 33 43 38 42 44 38 30 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\37790E2D198DFD20C9D2887D4EF7C3E2951BB84248D192689B64DCCA3C8BD808.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_AG_2147832085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.AG"
        threat_id = "2147832085"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:1F2F83AA634455DE2FF21DE1CFBF3D5963E666FCFDDA18D3071D2B5F27012F7E" wide //weight: 1
        $x_1_2 = {31 46 32 46 38 33 41 41 36 33 34 34 35 35 44 45 32 46 46 32 31 44 45 31 43 46 42 46 33 44 35 39 36 33 45 36 36 36 46 43 46 44 44 41 31 38 44 33 30 37 31 44 32 42 35 46 32 37 30 31 32 46 37 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {31 46 32 46 38 33 41 41 36 33 34 34 35 35 44 45 32 46 46 32 31 44 45 31 43 46 42 46 33 44 35 39 36 33 45 36 36 36 46 43 46 44 44 41 31 38 44 33 30 37 31 44 32 42 35 46 32 37 30 31 32 46 37 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\1F2F83AA634455DE2FF21DE1CFBF3D5963E666FCFDDA18D3071D2B5F27012F7E.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_AH_2147832475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.AH"
        threat_id = "2147832475"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:92392B907E97561DEDB20D1005D20910334AD3E72B8E1AB003BB1F4A53FFB072" wide //weight: 1
        $x_1_2 = {39 32 33 39 32 42 39 30 37 45 39 37 35 36 31 44 45 44 42 32 30 44 31 30 30 35 44 32 30 39 31 30 33 33 34 41 44 33 45 37 32 42 38 45 31 41 42 30 30 33 42 42 31 46 34 41 35 33 46 46 42 30 37 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {39 32 33 39 32 42 39 30 37 45 39 37 35 36 31 44 45 44 42 32 30 44 31 30 30 35 44 32 30 39 31 30 33 33 34 41 44 33 45 37 32 42 38 45 31 41 42 30 30 33 42 42 31 46 34 41 35 33 46 46 42 30 37 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\92392B907E97561DEDB20D1005D20910334AD3E72B8E1AB003BB1F4A53FFB072.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_AI_2147833373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.AI"
        threat_id = "2147833373"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:C1BDC6949510F7879F0782A3286392BFCC124E3393BD66592D84EEF135421D47" wide //weight: 1
        $x_1_2 = {43 31 42 44 43 36 39 34 39 35 31 30 46 37 38 37 39 46 30 37 38 32 41 33 32 38 36 33 39 32 42 46 43 43 31 32 34 45 33 33 39 33 42 44 36 36 35 39 32 44 38 34 45 45 46 31 33 35 34 32 31 44 34 37 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {43 31 42 44 43 36 39 34 39 35 31 30 46 37 38 37 39 46 30 37 38 32 41 33 32 38 36 33 39 32 42 46 43 43 31 32 34 45 33 33 39 33 42 44 36 36 35 39 32 44 38 34 45 45 46 31 33 35 34 32 31 44 34 37 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\C1BDC6949510F7879F0782A3286392BFCC124E3393BD66592D84EEF135421D47.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_AJ_2147835204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.AJ"
        threat_id = "2147835204"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:047C485EF868D556627D71E891C2D112BD2594912B1DFE1C1AE0E1405D8A3364" wide //weight: 1
        $x_1_2 = {30 34 37 43 34 38 35 45 46 38 36 38 44 35 35 36 36 32 37 44 37 31 45 38 39 31 43 32 44 31 31 32 42 44 32 35 39 34 39 31 32 42 31 44 46 45 31 43 31 41 45 30 45 31 34 30 35 44 38 41 33 33 36 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {30 34 37 43 34 38 35 45 46 38 36 38 44 35 35 36 36 32 37 44 37 31 45 38 39 31 43 32 44 31 31 32 42 44 32 35 39 34 39 31 32 42 31 44 46 45 31 43 31 41 45 30 45 31 34 30 35 44 38 41 33 33 36 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\047C485EF868D556627D71E891C2D112BD2594912B1DFE1C1AE0E1405D8A3364.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_AK_2147841747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.AK"
        threat_id = "2147841747"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:0A07A62A3C798ED0A5225E2F56EA6EEECE5B97BBD86EA7A68A8F6A43FB5C9502" wide //weight: 1
        $x_1_2 = {30 41 30 37 41 36 32 41 33 43 37 39 38 45 44 30 41 35 32 32 35 45 32 46 35 36 45 41 36 45 45 45 43 45 35 42 39 37 42 42 44 38 36 45 41 37 41 36 38 41 38 46 36 41 34 33 46 42 35 43 39 35 30 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {30 41 30 37 41 36 32 41 33 43 37 39 38 45 44 30 41 35 32 32 35 45 32 46 35 36 45 41 36 45 45 45 43 45 35 42 39 37 42 42 44 38 36 45 41 37 41 36 38 41 38 46 36 41 34 33 46 42 35 43 39 35 30 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\0A07A62A3C798ED0A5225E2F56EA6EEECE5B97BBD86EA7A68A8F6A43FB5C9502.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_AL_2147841751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.AL"
        threat_id = "2147841751"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tox:D6C324719AD0AA50A54E4F8DED8E8220D8698DD67B218B5429466C40E7F72657" wide //weight: 1
        $x_1_2 = {44 36 43 33 32 34 37 31 39 41 44 30 41 41 35 30 41 35 34 45 34 46 38 44 45 44 38 45 38 32 32 30 44 38 36 39 38 44 44 36 37 42 32 31 38 42 35 34 32 39 34 36 36 43 34 30 45 37 46 37 32 36 35 37 90 01 0c 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {44 36 43 33 32 34 37 31 39 41 44 30 41 41 35 30 41 35 34 45 34 46 38 44 45 44 38 45 38 32 32 30 44 38 36 39 38 44 44 36 37 42 32 31 38 42 35 34 32 39 34 36 36 43 34 30 45 37 46 37 32 36 35 37 90 01 0c 4c 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "\\tox\\D6C324719AD0AA50A54E4F8DED8E8220D8698DD67B218B5429466C40E7F72657.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_AM_2147841755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.AM"
        threat_id = "2147841755"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tox:AB33BC51AFAC64D98226826E70B483593C81CB22E6A3B504F7A75348C38C862F" wide //weight: 1
        $x_1_2 = {41 42 33 33 42 43 35 31 41 46 41 43 36 34 44 39 38 32 32 36 38 32 36 45 37 30 42 34 38 33 35 39 33 43 38 31 43 42 32 32 45 36 41 33 42 35 30 34 46 37 41 37 35 33 34 38 43 33 38 43 38 36 32 46 90 01 0c 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {41 42 33 33 42 43 35 31 41 46 41 43 36 34 44 39 38 32 32 36 38 32 36 45 37 30 42 34 38 33 35 39 33 43 38 31 43 42 32 32 45 36 41 33 42 35 30 34 46 37 41 37 35 33 34 38 43 33 38 43 38 36 32 46 90 01 0c 4c 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "\\tox\\AB33BC51AFAC64D98226826E70B483593C81CB22E6A3B504F7A75348C38C862F.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_AN_2147841968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.AN"
        threat_id = "2147841968"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tox:70A6C767835311185DB9A53970FE18D30A4F876B11E470BE99A4B399C712316B" wide //weight: 1
        $x_1_2 = {37 30 41 36 43 37 36 37 38 33 35 33 31 31 31 38 35 44 42 39 41 35 33 39 37 30 46 45 31 38 44 33 30 41 34 46 38 37 36 42 31 31 45 34 37 30 42 45 39 39 41 34 42 33 39 39 43 37 31 32 33 31 36 42 90 01 0c 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {37 30 41 36 43 37 36 37 38 33 35 33 31 31 31 38 35 44 42 39 41 35 33 39 37 30 46 45 31 38 44 33 30 41 34 46 38 37 36 42 31 31 45 34 37 30 42 45 39 39 41 34 42 33 39 39 43 37 31 32 33 31 36 42 90 01 0c 4c 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "\\tox\\70A6C767835311185DB9A53970FE18D30A4F876B11E470BE99A4B399C712316B.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_AO_2147841972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.AO"
        threat_id = "2147841972"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tox:4A7F41CC6A5B87AF99450066F313C224D4E0E5501414670A8C5B802403E6292F" wide //weight: 1
        $x_1_2 = {34 41 37 46 34 31 43 43 36 41 35 42 38 37 41 46 39 39 34 35 30 30 36 36 46 33 31 33 43 32 32 34 44 34 45 30 45 35 35 30 31 34 31 34 36 37 30 41 38 43 35 42 38 30 32 34 30 33 45 36 32 39 32 46 90 01 0c 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {34 41 37 46 34 31 43 43 36 41 35 42 38 37 41 46 39 39 34 35 30 30 36 36 46 33 31 33 43 32 32 34 44 34 45 30 45 35 35 30 31 34 31 34 36 37 30 41 38 43 35 42 38 30 32 34 30 33 45 36 32 39 32 46 90 01 0c 4c 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "\\tox\\4A7F41CC6A5B87AF99450066F313C224D4E0E5501414670A8C5B802403E6292F.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_AP_2147844843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.AP"
        threat_id = "2147844843"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tox:EBBB598994F84A48470423157C23FD9E76CD7AA05BE5602BDB50E13CA82F7838" wide //weight: 1
        $x_1_2 = {45 42 42 42 35 39 38 39 39 34 46 38 34 41 34 38 34 37 30 34 32 33 31 35 37 43 32 33 46 44 39 45 37 36 43 44 37 41 41 30 35 42 45 35 36 30 32 42 44 42 35 30 45 31 33 43 41 38 32 46 37 38 33 38 90 01 0c 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {45 42 42 42 35 39 38 39 39 34 46 38 34 41 34 38 34 37 30 34 32 33 31 35 37 43 32 33 46 44 39 45 37 36 43 44 37 41 41 30 35 42 45 35 36 30 32 42 44 42 35 30 45 31 33 43 41 38 32 46 37 38 33 38 90 01 0c 4c 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "\\tox\\EBBB598994F84A48470423157C23FD9E76CD7AA05BE5602BDB50E13CA82F7838.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_AQ_2147844847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.AQ"
        threat_id = "2147844847"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tox:A746E398A5BC9AD9F281F5D10CF861546092D0F2107F12EA9F107EFB7D21CA41" wide //weight: 1
        $x_1_2 = {41 37 34 36 45 33 39 38 41 35 42 43 39 41 44 39 46 32 38 31 46 35 44 31 30 43 46 38 36 31 35 34 36 30 39 32 44 30 46 32 31 30 37 46 31 32 45 41 39 46 31 30 37 45 46 42 37 44 32 31 43 41 34 31 90 01 0c 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {41 37 34 36 45 33 39 38 41 35 42 43 39 41 44 39 46 32 38 31 46 35 44 31 30 43 46 38 36 31 35 34 36 30 39 32 44 30 46 32 31 30 37 46 31 32 45 41 39 46 31 30 37 45 46 42 37 44 32 31 43 41 34 31 90 01 0c 4c 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "\\tox\\A746E398A5BC9AD9F281F5D10CF861546092D0F2107F12EA9F107EFB7D21CA41.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_AR_2147844851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.AR"
        threat_id = "2147844851"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tox:A4B3B0845DA242A64BF17E0DB4278EDF85855739667D3E2AE8B89D5439015F07" wide //weight: 1
        $x_1_2 = {41 34 42 33 42 30 38 34 35 44 41 32 34 32 41 36 34 42 46 31 37 45 30 44 42 34 32 37 38 45 44 46 38 35 38 35 35 37 33 39 36 36 37 44 33 45 32 41 45 38 42 38 39 44 35 34 33 39 30 31 35 46 30 37 90 01 0c 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {41 34 42 33 42 30 38 34 35 44 41 32 34 32 41 36 34 42 46 31 37 45 30 44 42 34 32 37 38 45 44 46 38 35 38 35 35 37 33 39 36 36 37 44 33 45 32 41 45 38 42 38 39 44 35 34 33 39 30 31 35 46 30 37 90 01 0c 4c 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "\\tox\\A4B3B0845DA242A64BF17E0DB4278EDF85855739667D3E2AE8B89D5439015F07.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_AS_2147844855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.AS"
        threat_id = "2147844855"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tox:2065307A4522EBFA9C862DB7C20033B71D882EBA11D0E14208721BD1EC64551C" wide //weight: 1
        $x_1_2 = {32 30 36 35 33 30 37 41 34 35 32 32 45 42 46 41 39 43 38 36 32 44 42 37 43 32 30 30 33 33 42 37 31 44 38 38 32 45 42 41 31 31 44 30 45 31 34 32 30 38 37 32 31 42 44 31 45 43 36 34 35 35 31 43 90 01 0c 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {32 30 36 35 33 30 37 41 34 35 32 32 45 42 46 41 39 43 38 36 32 44 42 37 43 32 30 30 33 33 42 37 31 44 38 38 32 45 42 41 31 31 44 30 45 31 34 32 30 38 37 32 31 42 44 31 45 43 36 34 35 35 31 43 90 01 0c 4c 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "\\tox\\2065307A4522EBFA9C862DB7C20033B71D882EBA11D0E14208721BD1EC64551C.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_AT_2147844859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.AT"
        threat_id = "2147844859"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tox:9FE0CA434933D63AA72E6037F87AF3E1FBBE698346268CCDE6CCC30E037EC602" wide //weight: 1
        $x_1_2 = {39 46 45 30 43 41 34 33 34 39 33 33 44 36 33 41 41 37 32 45 36 30 33 37 46 38 37 41 46 33 45 31 46 42 42 45 36 39 38 33 34 36 32 36 38 43 43 44 45 36 43 43 43 33 30 45 30 33 37 45 43 36 30 32 90 01 0c 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {39 46 45 30 43 41 34 33 34 39 33 33 44 36 33 41 41 37 32 45 36 30 33 37 46 38 37 41 46 33 45 31 46 42 42 45 36 39 38 33 34 36 32 36 38 43 43 44 45 36 43 43 43 33 30 45 30 33 37 45 43 36 30 32 90 01 0c 4c 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "\\tox\\9FE0CA434933D63AA72E6037F87AF3E1FBBE698346268CCDE6CCC30E037EC602.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_AU_2147845179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.AU"
        threat_id = "2147845179"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tox:E58D2154A7CAA8172E8AD15159AF1B1B3322E50A35D5821A29BC48D25143D33F" wide //weight: 1
        $x_1_2 = {45 35 38 44 32 31 35 34 41 37 43 41 41 38 31 37 32 45 38 41 44 31 35 31 35 39 41 46 31 42 31 42 33 33 32 32 45 35 30 41 33 35 44 35 38 32 31 41 32 39 42 43 34 38 44 32 35 31 34 33 44 33 33 46 90 01 0c 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {45 35 38 44 32 31 35 34 41 37 43 41 41 38 31 37 32 45 38 41 44 31 35 31 35 39 41 46 31 42 31 42 33 33 32 32 45 35 30 41 33 35 44 35 38 32 31 41 32 39 42 43 34 38 44 32 35 31 34 33 44 33 33 46 90 01 0c 4c 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "\\tox\\E58D2154A7CAA8172E8AD15159AF1B1B3322E50A35D5821A29BC48D25143D33F.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_AV_2147845183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.AV"
        threat_id = "2147845183"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tox:A4D33CD121274DF98FB5C256E44562ED61E1BE5333BCC9D7605960499E3C6F1B" wide //weight: 1
        $x_1_2 = {41 34 44 33 33 43 44 31 32 31 32 37 34 44 46 39 38 46 42 35 43 32 35 36 45 34 34 35 36 32 45 44 36 31 45 31 42 45 35 33 33 33 42 43 43 39 44 37 36 30 35 39 36 30 34 39 39 45 33 43 36 46 31 42 90 01 0c 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {41 34 44 33 33 43 44 31 32 31 32 37 34 44 46 39 38 46 42 35 43 32 35 36 45 34 34 35 36 32 45 44 36 31 45 31 42 45 35 33 33 33 42 43 43 39 44 37 36 30 35 39 36 30 34 39 39 45 33 43 36 46 31 42 90 01 0c 4c 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "\\tox\\A4D33CD121274DF98FB5C256E44562ED61E1BE5333BCC9D7605960499E3C6F1B.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_AW_2147845187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.AW"
        threat_id = "2147845187"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tox:A5852A300E402AD8AA973E1147D024FFE7DCF34BCC203C7B9DFB8560A3B10361" wide //weight: 1
        $x_1_2 = {41 35 38 35 32 41 33 30 30 45 34 30 32 41 44 38 41 41 39 37 33 45 31 31 34 37 44 30 32 34 46 46 45 37 44 43 46 33 34 42 43 43 32 30 33 43 37 42 39 44 46 42 38 35 36 30 41 33 42 31 30 33 36 31 90 01 0c 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {41 35 38 35 32 41 33 30 30 45 34 30 32 41 44 38 41 41 39 37 33 45 31 31 34 37 44 30 32 34 46 46 45 37 44 43 46 33 34 42 43 43 32 30 33 43 37 42 39 44 46 42 38 35 36 30 41 33 42 31 30 33 36 31 90 01 0c 4c 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "\\tox\\A5852A300E402AD8AA973E1147D024FFE7DCF34BCC203C7B9DFB8560A3B10361.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_AX_2147845913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.AX"
        threat_id = "2147845913"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tox:7367B422CD7498D5F2AAF33F58F67A332F8520CF0279A5FBB4611E0121AE421A" wide //weight: 1
        $x_1_2 = {37 33 36 37 42 34 32 32 43 44 37 34 39 38 44 35 46 32 41 41 46 33 33 46 35 38 46 36 37 41 33 33 32 46 38 35 32 30 43 46 30 32 37 39 41 35 46 42 42 34 36 31 31 45 30 31 32 31 41 45 34 32 31 41 90 01 0c 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {37 33 36 37 42 34 32 32 43 44 37 34 39 38 44 35 46 32 41 41 46 33 33 46 35 38 46 36 37 41 33 33 32 46 38 35 32 30 43 46 30 32 37 39 41 35 46 42 42 34 36 31 31 45 30 31 32 31 41 45 34 32 31 41 90 01 0c 4c 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "\\tox\\7367B422CD7498D5F2AAF33F58F67A332F8520CF0279A5FBB4611E0121AE421A.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_AY_2147846947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.AY"
        threat_id = "2147846947"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tox:E3213A199CDA7618AC22486EFECBD9F8E049AC36094D56AC1BFBE67EB9C3CF23" wide //weight: 1
        $x_1_2 = {45 33 32 31 33 41 31 39 39 43 44 41 37 36 31 38 41 43 32 32 34 38 36 45 46 45 43 42 44 39 46 38 45 30 34 39 41 43 33 36 30 39 34 44 35 36 41 43 31 42 46 42 45 36 37 45 42 39 43 33 43 46 32 33 90 01 0c 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {45 33 32 31 33 41 31 39 39 43 44 41 37 36 31 38 41 43 32 32 34 38 36 45 46 45 43 42 44 39 46 38 45 30 34 39 41 43 33 36 30 39 34 44 35 36 41 43 31 42 46 42 45 36 37 45 42 39 43 33 43 46 32 33 90 01 0c 4c 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "\\tox\\E3213A199CDA7618AC22486EFECBD9F8E049AC36094D56AC1BFBE67EB9C3CF23.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_AZ_2147846960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.AZ"
        threat_id = "2147846960"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tox:0ACA3AD2BD96541F66616CC088342107CF9F28997C1F697E50864393B8B82913" wide //weight: 1
        $x_1_2 = {30 41 43 41 33 41 44 32 42 44 39 36 35 34 31 46 36 36 36 31 36 43 43 30 38 38 33 34 32 31 30 37 43 46 39 46 32 38 39 39 37 43 31 46 36 39 37 45 35 30 38 36 34 33 39 33 42 38 42 38 32 39 31 33 90 01 0c 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {30 41 43 41 33 41 44 32 42 44 39 36 35 34 31 46 36 36 36 31 36 43 43 30 38 38 33 34 32 31 30 37 43 46 39 46 32 38 39 39 37 43 31 46 36 39 37 45 35 30 38 36 34 33 39 33 42 38 42 38 32 39 31 33 90 01 0c 4c 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "\\tox\\0ACA3AD2BD96541F66616CC088342107CF9F28997C1F697E50864393B8B82913.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_BA_2147847184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.BA"
        threat_id = "2147847184"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tox:6B76005FF5B3739B44CE38F0F4452C0DF2433F7B44B522DCD17B6151A6617744" wide //weight: 1
        $x_1_2 = {36 42 37 36 30 30 35 46 46 35 42 33 37 33 39 42 34 34 43 45 33 38 46 30 46 34 34 35 32 43 30 44 46 32 34 33 33 46 37 42 34 34 42 35 32 32 44 43 44 31 37 42 36 31 35 31 41 36 36 31 37 37 34 34 90 01 0c 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {36 42 37 36 30 30 35 46 46 35 42 33 37 33 39 42 34 34 43 45 33 38 46 30 46 34 34 35 32 43 30 44 46 32 34 33 33 46 37 42 34 34 42 35 32 32 44 43 44 31 37 42 36 31 35 31 41 36 36 31 37 37 34 34 90 01 0c 4c 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "\\tox\\6B76005FF5B3739B44CE38F0F4452C0DF2433F7B44B522DCD17B6151A6617744.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_BB_2147847677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.BB"
        threat_id = "2147847677"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tox:71FE82F1B76CAFD9A75E71B42CBA46824DBF0F1F3506ABF8EE0CB7BF40F73D4A" wide //weight: 1
        $x_1_2 = {37 31 46 45 38 32 46 31 42 37 36 43 41 46 44 39 41 37 35 45 37 31 42 34 32 43 42 41 34 36 38 32 34 44 42 46 30 46 31 46 33 35 30 36 41 42 46 38 45 45 30 43 42 37 42 46 34 30 46 37 33 44 34 41 90 01 0c 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {37 31 46 45 38 32 46 31 42 37 36 43 41 46 44 39 41 37 35 45 37 31 42 34 32 43 42 41 34 36 38 32 34 44 42 46 30 46 31 46 33 35 30 36 41 42 46 38 45 45 30 43 42 37 42 46 34 30 46 37 33 44 34 41 90 01 0c 4c 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "\\tox\\71FE82F1B76CAFD9A75E71B42CBA46824DBF0F1F3506ABF8EE0CB7BF40F73D4A.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_BC_2147847681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.BC"
        threat_id = "2147847681"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tox:2FE7DA695F96154B1EC5AE05E9BBBACDF976FC5FFD9D1D4FDC34B79DBA02A432" wide //weight: 1
        $x_1_2 = {32 46 45 37 44 41 36 39 35 46 39 36 31 35 34 42 31 45 43 35 41 45 30 35 45 39 42 42 42 41 43 44 46 39 37 36 46 43 35 46 46 44 39 44 31 44 34 46 44 43 33 34 42 37 39 44 42 41 30 32 41 34 33 32 90 01 0c 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {32 46 45 37 44 41 36 39 35 46 39 36 31 35 34 42 31 45 43 35 41 45 30 35 45 39 42 42 42 41 43 44 46 39 37 36 46 43 35 46 46 44 39 44 31 44 34 46 44 43 33 34 42 37 39 44 42 41 30 32 41 34 33 32 90 01 0c 4c 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "\\tox\\2FE7DA695F96154B1EC5AE05E9BBBACDF976FC5FFD9D1D4FDC34B79DBA02A432.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_BD_2147849195_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.BD"
        threat_id = "2147849195"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:3F2A79CEDC9328540DF8E75682A36DA326E612ABBF9CBA6FC510EAF53D2EE608" wide //weight: 1
        $x_1_2 = {33 46 32 41 37 39 43 45 44 43 39 33 32 38 35 34 30 44 46 38 45 37 35 36 38 32 41 33 36 44 41 33 32 36 45 36 31 32 41 42 42 46 39 43 42 41 36 46 43 35 31 30 45 41 46 35 33 44 32 45 45 36 30 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {33 46 32 41 37 39 43 45 44 43 39 33 32 38 35 34 30 44 46 38 45 37 35 36 38 32 41 33 36 44 41 33 32 36 45 36 31 32 41 42 42 46 39 43 42 41 36 46 43 35 31 30 45 41 46 35 33 44 32 45 45 36 30 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\3F2A79CEDC9328540DF8E75682A36DA326E612ABBF9CBA6FC510EAF53D2EE608.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_BE_2147849199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.BE"
        threat_id = "2147849199"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:8F0E308CB4D9F1F3F80EC93A4C566B8CFCCAB0967F0637C00ED3079C37235652" wide //weight: 1
        $x_1_2 = {38 46 30 45 33 30 38 43 42 34 44 39 46 31 46 33 46 38 30 45 43 39 33 41 34 43 35 36 36 42 38 43 46 43 43 41 42 30 39 36 37 46 30 36 33 37 43 30 30 45 44 33 30 37 39 43 33 37 32 33 35 36 35 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {38 46 30 45 33 30 38 43 42 34 44 39 46 31 46 33 46 38 30 45 43 39 33 41 34 43 35 36 36 42 38 43 46 43 43 41 42 30 39 36 37 46 30 36 33 37 43 30 30 45 44 33 30 37 39 43 33 37 32 33 35 36 35 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\8F0E308CB4D9F1F3F80EC93A4C566B8CFCCAB0967F0637C00ED3079C37235652.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_BF_2147849658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.BF"
        threat_id = "2147849658"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:DBA5908245E3067FDA9B0C0D6FEEADC3D3C965A29AC340CA14D539924700DC53" wide //weight: 1
        $x_1_2 = {44 42 41 35 39 30 38 32 34 35 45 33 30 36 37 46 44 41 39 42 30 43 30 44 36 46 45 45 41 44 43 33 44 33 43 39 36 35 41 32 39 41 43 33 34 30 43 41 31 34 44 35 33 39 39 32 34 37 30 30 44 43 35 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {44 42 41 35 39 30 38 32 34 35 45 33 30 36 37 46 44 41 39 42 30 43 30 44 36 46 45 45 41 44 43 33 44 33 43 39 36 35 41 32 39 41 43 33 34 30 43 41 31 34 44 35 33 39 39 32 34 37 30 30 44 43 35 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\DBA5908245E3067FDA9B0C0D6FEEADC3D3C965A29AC340CA14D539924700DC53.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_BG_2147849868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.BG"
        threat_id = "2147849868"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:E9CD65687463F67F64937E961DD723DC82C79CB548375AAE8AA4A0698D356C5E" wide //weight: 1
        $x_1_2 = {45 39 43 44 36 35 36 38 37 34 36 33 46 36 37 46 36 34 39 33 37 45 39 36 31 44 44 37 32 33 44 43 38 32 43 37 39 43 42 35 34 38 33 37 35 41 41 45 38 41 41 34 41 30 36 39 38 44 33 35 36 43 35 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {45 39 43 44 36 35 36 38 37 34 36 33 46 36 37 46 36 34 39 33 37 45 39 36 31 44 44 37 32 33 44 43 38 32 43 37 39 43 42 35 34 38 33 37 35 41 41 45 38 41 41 34 41 30 36 39 38 44 33 35 36 43 35 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\E9CD65687463F67F64937E961DD723DC82C79CB548375AAE8AA4A0698D356C5E.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_BH_2147849872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.BH"
        threat_id = "2147849872"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:7043099A06D401A1F441F2FAD54FC2072A52FD6D250893B73C372448FAFDCE08" wide //weight: 1
        $x_1_2 = {37 30 34 33 30 39 39 41 30 36 44 34 30 31 41 31 46 34 34 31 46 32 46 41 44 35 34 46 43 32 30 37 32 41 35 32 46 44 36 44 32 35 30 38 39 33 42 37 33 43 33 37 32 34 34 38 46 41 46 44 43 45 30 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {37 30 34 33 30 39 39 41 30 36 44 34 30 31 41 31 46 34 34 31 46 32 46 41 44 35 34 46 43 32 30 37 32 41 35 32 46 44 36 44 32 35 30 38 39 33 42 37 33 43 33 37 32 34 34 38 46 41 46 44 43 45 30 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\7043099A06D401A1F441F2FAD54FC2072A52FD6D250893B73C372448FAFDCE08.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_BI_2147850060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.BI"
        threat_id = "2147850060"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:77A904360EA7D74268E7A4F316865F1703D2D7A6AF28C9ECFACED69CD09C8610" wide //weight: 1
        $x_1_2 = {37 37 41 39 30 34 33 36 30 45 41 37 44 37 34 32 36 38 45 37 41 34 46 33 31 36 38 36 35 46 31 37 30 33 44 32 44 37 41 36 41 46 32 38 43 39 45 43 46 41 43 45 44 36 39 43 44 30 39 43 38 36 31 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {37 37 41 39 30 34 33 36 30 45 41 37 44 37 34 32 36 38 45 37 41 34 46 33 31 36 38 36 35 46 31 37 30 33 44 32 44 37 41 36 41 46 32 38 43 39 45 43 46 41 43 45 44 36 39 43 44 30 39 43 38 36 31 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\77A904360EA7D74268E7A4F316865F1703D2D7A6AF28C9ECFACED69CD09C8610.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_BJ_2147850064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.BJ"
        threat_id = "2147850064"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:84032B92D37C888FD3572909059BD6FA77612DD4FE62B4587A48DE33322AB67E" wide //weight: 1
        $x_1_2 = {38 34 30 33 32 42 39 32 44 33 37 43 38 38 38 46 44 33 35 37 32 39 30 39 30 35 39 42 44 36 46 41 37 37 36 31 32 44 44 34 46 45 36 32 42 34 35 38 37 41 34 38 44 45 33 33 33 32 32 41 42 36 37 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {38 34 30 33 32 42 39 32 44 33 37 43 38 38 38 46 44 33 35 37 32 39 30 39 30 35 39 42 44 36 46 41 37 37 36 31 32 44 44 34 46 45 36 32 42 34 35 38 37 41 34 38 44 45 33 33 33 32 32 41 42 36 37 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\84032B92D37C888FD3572909059BD6FA77612DD4FE62B4587A48DE33322AB67E.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_BK_2147850835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.BK"
        threat_id = "2147850835"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:8B7C5C04B7431200645C9E190BB1EFABBFB3826810AAFCFF01ACF9B4080E5502" wide //weight: 1
        $x_1_2 = {38 42 37 43 35 43 30 34 42 37 34 33 31 32 30 30 36 34 35 43 39 45 31 39 30 42 42 31 45 46 41 42 42 46 42 33 38 32 36 38 31 30 41 41 46 43 46 46 30 31 41 43 46 39 42 34 30 38 30 45 35 35 30 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {38 42 37 43 35 43 30 34 42 37 34 33 31 32 30 30 36 34 35 43 39 45 31 39 30 42 42 31 45 46 41 42 42 46 42 33 38 32 36 38 31 30 41 41 46 43 46 46 30 31 41 43 46 39 42 34 30 38 30 45 35 35 30 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\8B7C5C04B7431200645C9E190BB1EFABBFB3826810AAFCFF01ACF9B4080E5502.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_BL_2147851103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.BL"
        threat_id = "2147851103"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:BC9132FAE386CD10790AB21400CF248D56DFEC29E5403C144ACCA8D426D68B33" wide //weight: 1
        $x_1_2 = {42 43 39 31 33 32 46 41 45 33 38 36 43 44 31 30 37 39 30 41 42 32 31 34 30 30 43 46 32 34 38 44 35 36 44 46 45 43 32 39 45 35 34 30 33 43 31 34 34 41 43 43 41 38 44 34 32 36 44 36 38 42 33 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {42 43 39 31 33 32 46 41 45 33 38 36 43 44 31 30 37 39 30 41 42 32 31 34 30 30 43 46 32 34 38 44 35 36 44 46 45 43 32 39 45 35 34 30 33 43 31 34 34 41 43 43 41 38 44 34 32 36 44 36 38 42 33 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\BC9132FAE386CD10790AB21400CF248D56DFEC29E5403C144ACCA8D426D68B33.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_BM_2147851924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.BM"
        threat_id = "2147851924"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:126E30C4CC9DE90F79D1FA90830FDC2069A2E981ED26B6DC148DA8827FB3D63A" wide //weight: 1
        $x_1_2 = {31 32 36 45 33 30 43 34 43 43 39 44 45 39 30 46 37 39 44 31 46 41 39 30 38 33 30 46 44 43 32 30 36 39 41 32 45 39 38 31 45 44 32 36 42 36 44 43 31 34 38 44 41 38 38 32 37 46 42 33 44 36 33 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {31 32 36 45 33 30 43 34 43 43 39 44 45 39 30 46 37 39 44 31 46 41 39 30 38 33 30 46 44 43 32 30 36 39 41 32 45 39 38 31 45 44 32 36 42 36 44 43 31 34 38 44 41 38 38 32 37 46 42 33 44 36 33 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\126E30C4CC9DE90F79D1FA90830FDC2069A2E981ED26B6DC148DA8827FB3D63A.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_BN_2147852258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.BN"
        threat_id = "2147852258"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:A7B9AD23F5AC4AB5404BFDE1E67CE0797F4FFD1C79D8A539E17406A55D5ED93B" wide //weight: 1
        $x_1_2 = {41 37 42 39 41 44 32 33 46 35 41 43 34 41 42 35 34 30 34 42 46 44 45 31 45 36 37 43 45 30 37 39 37 46 34 46 46 44 31 43 37 39 44 38 41 35 33 39 45 31 37 34 30 36 41 35 35 44 35 45 44 39 33 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {41 37 42 39 41 44 32 33 46 35 41 43 34 41 42 35 34 30 34 42 46 44 45 31 45 36 37 43 45 30 37 39 37 46 34 46 46 44 31 43 37 39 44 38 41 35 33 39 45 31 37 34 30 36 41 35 35 44 35 45 44 39 33 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\A7B9AD23F5AC4AB5404BFDE1E67CE0797F4FFD1C79D8A539E17406A55D5ED93B.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_BO_2147853056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.BO"
        threat_id = "2147853056"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:78E21CFF7AA85F713C1530AEF2E74E62830BEE77238F4B0A73E5E3251EAD5642" wide //weight: 1
        $x_1_2 = {37 38 45 32 31 43 46 46 37 41 41 38 35 46 37 31 33 43 31 35 33 30 41 45 46 32 45 37 34 45 36 32 38 33 30 42 45 45 37 37 32 33 38 46 34 42 30 41 37 33 45 35 45 33 32 35 31 45 41 44 35 36 34 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {37 38 45 32 31 43 46 46 37 41 41 38 35 46 37 31 33 43 31 35 33 30 41 45 46 32 45 37 34 45 36 32 38 33 30 42 45 45 37 37 32 33 38 46 34 42 30 41 37 33 45 35 45 33 32 35 31 45 41 44 35 36 34 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\78E21CFF7AA85F713C1530AEF2E74E62830BEE77238F4B0A73E5E3251EAD5642.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_BP_2147853060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.BP"
        threat_id = "2147853060"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:81A9E67702D5AB17E1CF43296D6FAE7EB8DE6B2DDD69D58404CB19477CCA6B64" wide //weight: 1
        $x_1_2 = {38 31 41 39 45 36 37 37 30 32 44 35 41 42 31 37 45 31 43 46 34 33 32 39 36 44 36 46 41 45 37 45 42 38 44 45 36 42 32 44 44 44 36 39 44 35 38 34 30 34 43 42 31 39 34 37 37 43 43 41 36 42 36 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {38 31 41 39 45 36 37 37 30 32 44 35 41 42 31 37 45 31 43 46 34 33 32 39 36 44 36 46 41 45 37 45 42 38 44 45 36 42 32 44 44 44 36 39 44 35 38 34 30 34 43 42 31 39 34 37 37 43 43 41 36 42 36 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\81A9E67702D5AB17E1CF43296D6FAE7EB8DE6B2DDD69D58404CB19477CCA6B64.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_BQ_2147853437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.BQ"
        threat_id = "2147853437"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:9096AD7062A4232F5AA31C2F7C4DF0AC1EAD10B78D40A6A3328AD142A42B555E" wide //weight: 1
        $x_1_2 = {39 30 39 36 41 44 37 30 36 32 41 34 32 33 32 46 35 41 41 33 31 43 32 46 37 43 34 44 46 30 41 43 31 45 41 44 31 30 42 37 38 44 34 30 41 36 41 33 33 32 38 41 44 31 34 32 41 34 32 42 35 35 35 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {39 30 39 36 41 44 37 30 36 32 41 34 32 33 32 46 35 41 41 33 31 43 32 46 37 43 34 44 46 30 41 43 31 45 41 44 31 30 42 37 38 44 34 30 41 36 41 33 33 32 38 41 44 31 34 32 41 34 32 42 35 35 35 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\9096AD7062A4232F5AA31C2F7C4DF0AC1EAD10B78D40A6A3328AD142A42B555E.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_BR_2147853441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.BR"
        threat_id = "2147853441"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:4AE245548F2A225882951FB14E9BF87EE01A0C10AE159B99D1EA62620D91A372" wide //weight: 1
        $x_1_2 = {34 41 45 32 34 35 35 34 38 46 32 41 32 32 35 38 38 32 39 35 31 46 42 31 34 45 39 42 46 38 37 45 45 30 31 41 30 43 31 30 41 45 31 35 39 42 39 39 44 31 45 41 36 32 36 32 30 44 39 31 41 33 37 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {34 41 45 32 34 35 35 34 38 46 32 41 32 32 35 38 38 32 39 35 31 46 42 31 34 45 39 42 46 38 37 45 45 30 31 41 30 43 31 30 41 45 31 35 39 42 39 39 44 31 45 41 36 32 36 32 30 44 39 31 41 33 37 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\4AE245548F2A225882951FB14E9BF87EE01A0C10AE159B99D1EA62620D91A372.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_BS_2147888320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.BS"
        threat_id = "2147888320"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:A5F2F6058F70CE5953DC475EE6AF1F97FC6D487ABEBAE76915075E3A53525B1D" wide //weight: 1
        $x_1_2 = {41 35 46 32 46 36 30 35 38 46 37 30 43 45 35 39 35 33 44 43 34 37 35 45 45 36 41 46 31 46 39 37 46 43 36 44 34 38 37 41 42 45 42 41 45 37 36 39 31 35 30 37 35 45 33 41 35 33 35 32 35 42 31 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {41 35 46 32 46 36 30 35 38 46 37 30 43 45 35 39 35 33 44 43 34 37 35 45 45 36 41 46 31 46 39 37 46 43 36 44 34 38 37 41 42 45 42 41 45 37 36 39 31 35 30 37 35 45 33 41 35 33 35 32 35 42 31 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\A5F2F6058F70CE5953DC475EE6AF1F97FC6D487ABEBAE76915075E3A53525B1D.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_BT_2147888554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.BT"
        threat_id = "2147888554"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:3C9D49B928FDC3C15F0314217623A71B865909B308576B4B0D10AEA62C98677B" wide //weight: 1
        $x_1_2 = {33 43 39 44 34 39 42 39 32 38 46 44 43 33 43 31 35 46 30 33 31 34 32 31 37 36 32 33 41 37 31 42 38 36 35 39 30 39 42 33 30 38 35 37 36 42 34 42 30 44 31 30 41 45 41 36 32 43 39 38 36 37 37 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {33 43 39 44 34 39 42 39 32 38 46 44 43 33 43 31 35 46 30 33 31 34 32 31 37 36 32 33 41 37 31 42 38 36 35 39 30 39 42 33 30 38 35 37 36 42 34 42 30 44 31 30 41 45 41 36 32 43 39 38 36 37 37 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\3C9D49B928FDC3C15F0314217623A71B865909B308576B4B0D10AEA62C98677B.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_BU_2147888558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.BU"
        threat_id = "2147888558"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:4F15236BFB89FA84E292D30C007046511FE12FE35D4C0AEA74A15FB0E5A90848" wide //weight: 1
        $x_1_2 = {34 46 31 35 32 33 36 42 46 42 38 39 46 41 38 34 45 32 39 32 44 33 30 43 30 30 37 30 34 36 35 31 31 46 45 31 32 46 45 33 35 44 34 43 30 41 45 41 37 34 41 31 35 46 42 30 45 35 41 39 30 38 34 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {34 46 31 35 32 33 36 42 46 42 38 39 46 41 38 34 45 32 39 32 44 33 30 43 30 30 37 30 34 36 35 31 31 46 45 31 32 46 45 33 35 44 34 43 30 41 45 41 37 34 41 31 35 46 42 30 45 35 41 39 30 38 34 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\4F15236BFB89FA84E292D30C007046511FE12FE35D4C0AEA74A15FB0E5A90848.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_BV_2147888562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.BV"
        threat_id = "2147888562"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:192D52C7C18F3D2693ED2453E64C53EC0CCF0255AB2291F019B65BA84442B313" wide //weight: 1
        $x_1_2 = {31 39 32 44 35 32 43 37 43 31 38 46 33 44 32 36 39 33 45 44 32 34 35 33 45 36 34 43 35 33 45 43 30 43 43 46 30 32 35 35 41 42 32 32 39 31 46 30 31 39 42 36 35 42 41 38 34 34 34 32 42 33 31 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {31 39 32 44 35 32 43 37 43 31 38 46 33 44 32 36 39 33 45 44 32 34 35 33 45 36 34 43 35 33 45 43 30 43 43 46 30 32 35 35 41 42 32 32 39 31 46 30 31 39 42 36 35 42 41 38 34 34 34 32 42 33 31 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\192D52C7C18F3D2693ED2453E64C53EC0CCF0255AB2291F019B65BA84442B313.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_BW_2147888566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.BW"
        threat_id = "2147888566"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:0A6F992E1372DB4F245595424A7436EBB610775D6ADDC4D568ACC2AF5D315221" wide //weight: 1
        $x_1_2 = {30 41 36 46 39 39 32 45 31 33 37 32 44 42 34 46 32 34 35 35 39 35 34 32 34 41 37 34 33 36 45 42 42 36 31 30 37 37 35 44 36 41 44 44 43 34 44 35 36 38 41 43 43 32 41 46 35 44 33 31 35 32 32 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {30 41 36 46 39 39 32 45 31 33 37 32 44 42 34 46 32 34 35 35 39 35 34 32 34 41 37 34 33 36 45 42 42 36 31 30 37 37 35 44 36 41 44 44 43 34 44 35 36 38 41 43 43 32 41 46 35 44 33 31 35 32 32 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\0A6F992E1372DB4F245595424A7436EBB610775D6ADDC4D568ACC2AF5D315221.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_BX_2147888570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.BX"
        threat_id = "2147888570"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:3FA4D7B4989C059F50B12F28313210ADF04EE9DFE6C2F2AD1048048E92BD4D21" wide //weight: 1
        $x_1_2 = {33 46 41 34 44 37 42 34 39 38 39 43 30 35 39 46 35 30 42 31 32 46 32 38 33 31 33 32 31 30 41 44 46 30 34 45 45 39 44 46 45 36 43 32 46 32 41 44 31 30 34 38 30 34 38 45 39 32 42 44 34 44 32 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {33 46 41 34 44 37 42 34 39 38 39 43 30 35 39 46 35 30 42 31 32 46 32 38 33 31 33 32 31 30 41 44 46 30 34 45 45 39 44 46 45 36 43 32 46 32 41 44 31 30 34 38 30 34 38 45 39 32 42 44 34 44 32 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\3FA4D7B4989C059F50B12F28313210ADF04EE9DFE6C2F2AD1048048E92BD4D21.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_BY_2147888742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.BY"
        threat_id = "2147888742"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:9E1DEB410719C2CD0730E914BA2138795230F318A9EFBA6A5B43E722E9F76028" wide //weight: 1
        $x_1_2 = {39 45 31 44 45 42 34 31 30 37 31 39 43 32 43 44 30 37 33 30 45 39 31 34 42 41 32 31 33 38 37 39 35 32 33 30 46 33 31 38 41 39 45 46 42 41 36 41 35 42 34 33 45 37 32 32 45 39 46 37 36 30 32 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {39 45 31 44 45 42 34 31 30 37 31 39 43 32 43 44 30 37 33 30 45 39 31 34 42 41 32 31 33 38 37 39 35 32 33 30 46 33 31 38 41 39 45 46 42 41 36 41 35 42 34 33 45 37 32 32 45 39 46 37 36 30 32 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\9E1DEB410719C2CD0730E914BA2138795230F318A9EFBA6A5B43E722E9F76028.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_BZ_2147888746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.BZ"
        threat_id = "2147888746"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:87F021ADD4DD69217D3D5BB3B42DAB52F362D8ABE2A831CFE381D3C72BB0AC03" wide //weight: 1
        $x_1_2 = {38 37 46 30 32 31 41 44 44 34 44 44 36 39 32 31 37 44 33 44 35 42 42 33 42 34 32 44 41 42 35 32 46 33 36 32 44 38 41 42 45 32 41 38 33 31 43 46 45 33 38 31 44 33 43 37 32 42 42 30 41 43 30 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {38 37 46 30 32 31 41 44 44 34 44 44 36 39 32 31 37 44 33 44 35 42 42 33 42 34 32 44 41 42 35 32 46 33 36 32 44 38 41 42 45 32 41 38 33 31 43 46 45 33 38 31 44 33 43 37 32 42 42 30 41 43 30 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\87F021ADD4DD69217D3D5BB3B42DAB52F362D8ABE2A831CFE381D3C72BB0AC03.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_CA_2147888750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.CA"
        threat_id = "2147888750"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:CFAC328D48B8A1499A1E67423F60E502A22557558CEEDD77A1A3DE59B2144C38" wide //weight: 1
        $x_1_2 = {43 46 41 43 33 32 38 44 34 38 42 38 41 31 34 39 39 41 31 45 36 37 34 32 33 46 36 30 45 35 30 32 41 32 32 35 35 37 35 35 38 43 45 45 44 44 37 37 41 31 41 33 44 45 35 39 42 32 31 34 34 43 33 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {43 46 41 43 33 32 38 44 34 38 42 38 41 31 34 39 39 41 31 45 36 37 34 32 33 46 36 30 45 35 30 32 41 32 32 35 35 37 35 35 38 43 45 45 44 44 37 37 41 31 41 33 44 45 35 39 42 32 31 34 34 43 33 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\CFAC328D48B8A1499A1E67423F60E502A22557558CEEDD77A1A3DE59B2144C38.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_CB_2147888754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.CB"
        threat_id = "2147888754"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:75CD9D0B5D0E632A8850B619193E2DC69E55B5697B174D691C4CC72A88636E48" wide //weight: 1
        $x_1_2 = {37 35 43 44 39 44 30 42 35 44 30 45 36 33 32 41 38 38 35 30 42 36 31 39 31 39 33 45 32 44 43 36 39 45 35 35 42 35 36 39 37 42 31 37 34 44 36 39 31 43 34 43 43 37 32 41 38 38 36 33 36 45 34 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {37 35 43 44 39 44 30 42 35 44 30 45 36 33 32 41 38 38 35 30 42 36 31 39 31 39 33 45 32 44 43 36 39 45 35 35 42 35 36 39 37 42 31 37 34 44 36 39 31 43 34 43 43 37 32 41 38 38 36 33 36 45 34 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\75CD9D0B5D0E632A8850B619193E2DC69E55B5697B174D691C4CC72A88636E48.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_CC_2147888758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.CC"
        threat_id = "2147888758"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:D9A671DF6C004AA4850099AFDBA18DD1193B61A386745CD1DED8DEBBB36E0255" wide //weight: 1
        $x_1_2 = {44 39 41 36 37 31 44 46 36 43 30 30 34 41 41 34 38 35 30 30 39 39 41 46 44 42 41 31 38 44 44 31 31 39 33 42 36 31 41 33 38 36 37 34 35 43 44 31 44 45 44 38 44 45 42 42 42 33 36 45 30 32 35 35 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {44 39 41 36 37 31 44 46 36 43 30 30 34 41 41 34 38 35 30 30 39 39 41 46 44 42 41 31 38 44 44 31 31 39 33 42 36 31 41 33 38 36 37 34 35 43 44 31 44 45 44 38 44 45 42 42 42 33 36 45 30 32 35 35 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\D9A671DF6C004AA4850099AFDBA18DD1193B61A386745CD1DED8DEBBB36E0255.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_CD_2147888845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.CD"
        threat_id = "2147888845"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:AA7774431263F51F9043515C84C3186D7D685FEBC5AEA490272C75AE61473114" wide //weight: 1
        $x_1_2 = {41 41 37 37 37 34 34 33 31 32 36 33 46 35 31 46 39 30 34 33 35 31 35 43 38 34 43 33 31 38 36 44 37 44 36 38 35 46 45 42 43 35 41 45 41 34 39 30 32 37 32 43 37 35 41 45 36 31 34 37 33 31 31 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {41 41 37 37 37 34 34 33 31 32 36 33 46 35 31 46 39 30 34 33 35 31 35 43 38 34 43 33 31 38 36 44 37 44 36 38 35 46 45 42 43 35 41 45 41 34 39 30 32 37 32 43 37 35 41 45 36 31 34 37 33 31 31 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\AA7774431263F51F9043515C84C3186D7D685FEBC5AEA490272C75AE61473114.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_CE_2147888849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.CE"
        threat_id = "2147888849"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:274D8D5543770DADEEEE88E2B719C149462BF71AB0394EE5FF7FEBF22569EA64" wide //weight: 1
        $x_1_2 = {32 37 34 44 38 44 35 35 34 33 37 37 30 44 41 44 45 45 45 45 38 38 45 32 42 37 31 39 43 31 34 39 34 36 32 42 46 37 31 41 42 30 33 39 34 45 45 35 46 46 37 46 45 42 46 32 32 35 36 39 45 41 36 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {32 37 34 44 38 44 35 35 34 33 37 37 30 44 41 44 45 45 45 45 38 38 45 32 42 37 31 39 43 31 34 39 34 36 32 42 46 37 31 41 42 30 33 39 34 45 45 35 46 46 37 46 45 42 46 32 32 35 36 39 45 41 36 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\274D8D5543770DADEEEE88E2B719C149462BF71AB0394EE5FF7FEBF22569EA64.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_CF_2147888853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.CF"
        threat_id = "2147888853"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:6B494AC81C1ADFA4AD8DFFB3862F45EDB79703FDC8EE4C86B01956D17024EF5D" wide //weight: 1
        $x_1_2 = {36 42 34 39 34 41 43 38 31 43 31 41 44 46 41 34 41 44 38 44 46 46 42 33 38 36 32 46 34 35 45 44 42 37 39 37 30 33 46 44 43 38 45 45 34 43 38 36 42 30 31 39 35 36 44 31 37 30 32 34 45 46 35 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {36 42 34 39 34 41 43 38 31 43 31 41 44 46 41 34 41 44 38 44 46 46 42 33 38 36 32 46 34 35 45 44 42 37 39 37 30 33 46 44 43 38 45 45 34 43 38 36 42 30 31 39 35 36 44 31 37 30 32 34 45 46 35 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\6B494AC81C1ADFA4AD8DFFB3862F45EDB79703FDC8EE4C86B01956D17024EF5D.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_CG_2147888857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.CG"
        threat_id = "2147888857"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:839A2C1203F1C5D22579B2F646105A7FE8859A42160D4944543A77A38585FA1F" wide //weight: 1
        $x_1_2 = {38 33 39 41 32 43 31 32 30 33 46 31 43 35 44 32 32 35 37 39 42 32 46 36 34 36 31 30 35 41 37 46 45 38 38 35 39 41 34 32 31 36 30 44 34 39 34 34 35 34 33 41 37 37 41 33 38 35 38 35 46 41 31 46 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {38 33 39 41 32 43 31 32 30 33 46 31 43 35 44 32 32 35 37 39 42 32 46 36 34 36 31 30 35 41 37 46 45 38 38 35 39 41 34 32 31 36 30 44 34 39 34 34 35 34 33 41 37 37 41 33 38 35 38 35 46 41 31 46 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\839A2C1203F1C5D22579B2F646105A7FE8859A42160D4944543A77A38585FA1F.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_CH_2147888861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.CH"
        threat_id = "2147888861"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:30EE99903253BC5AE3D404A58AFE28BA373FE73E258A6537C68D7DA4E44E1368" wide //weight: 1
        $x_1_2 = {33 30 45 45 39 39 39 30 33 32 35 33 42 43 35 41 45 33 44 34 30 34 41 35 38 41 46 45 32 38 42 41 33 37 33 46 45 37 33 45 32 35 38 41 36 35 33 37 43 36 38 44 37 44 41 34 45 34 34 45 31 33 36 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {33 30 45 45 39 39 39 30 33 32 35 33 42 43 35 41 45 33 44 34 30 34 41 35 38 41 46 45 32 38 42 41 33 37 33 46 45 37 33 45 32 35 38 41 36 35 33 37 43 36 38 44 37 44 41 34 45 34 34 45 31 33 36 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\30EE99903253BC5AE3D404A58AFE28BA373FE73E258A6537C68D7DA4E44E1368.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_CI_2147888965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.CI"
        threat_id = "2147888965"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:A1684234F478AF4A32CF9539D997C324D5CEC14F9474A83544ABEFFD133C286F" wide //weight: 1
        $x_1_2 = {41 31 36 38 34 32 33 34 46 34 37 38 41 46 34 41 33 32 43 46 39 35 33 39 44 39 39 37 43 33 32 34 44 35 43 45 43 31 34 46 39 34 37 34 41 38 33 35 34 34 41 42 45 46 46 44 31 33 33 43 32 38 36 46 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {41 31 36 38 34 32 33 34 46 34 37 38 41 46 34 41 33 32 43 46 39 35 33 39 44 39 39 37 43 33 32 34 44 35 43 45 43 31 34 46 39 34 37 34 41 38 33 35 34 34 41 42 45 46 46 44 31 33 33 43 32 38 36 46 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\A1684234F478AF4A32CF9539D997C324D5CEC14F9474A83544ABEFFD133C286F.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_CJ_2147888969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.CJ"
        threat_id = "2147888969"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:2B41B398739E6BECE4E93EAFA0C665E3680C8C7B75C566A44C99C710BB524741" wide //weight: 1
        $x_1_2 = {32 42 34 31 42 33 39 38 37 33 39 45 36 42 45 43 45 34 45 39 33 45 41 46 41 30 43 36 36 35 45 33 36 38 30 43 38 43 37 42 37 35 43 35 36 36 41 34 34 43 39 39 43 37 31 30 42 42 35 32 34 37 34 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {32 42 34 31 42 33 39 38 37 33 39 45 36 42 45 43 45 34 45 39 33 45 41 46 41 30 43 36 36 35 45 33 36 38 30 43 38 43 37 42 37 35 43 35 36 36 41 34 34 43 39 39 43 37 31 30 42 42 35 32 34 37 34 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\2B41B398739E6BECE4E93EAFA0C665E3680C8C7B75C566A44C99C710BB524741.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_CK_2147888973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.CK"
        threat_id = "2147888973"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:B79A7B0B31CF36361487D7CB6E7874132B056528D8AA4146424A7D1ECA72BC44" wide //weight: 1
        $x_1_2 = {42 37 39 41 37 42 30 42 33 31 43 46 33 36 33 36 31 34 38 37 44 37 43 42 36 45 37 38 37 34 31 33 32 42 30 35 36 35 32 38 44 38 41 41 34 31 34 36 34 32 34 41 37 44 31 45 43 41 37 32 42 43 34 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {42 37 39 41 37 42 30 42 33 31 43 46 33 36 33 36 31 34 38 37 44 37 43 42 36 45 37 38 37 34 31 33 32 42 30 35 36 35 32 38 44 38 41 41 34 31 34 36 34 32 34 41 37 44 31 45 43 41 37 32 42 43 34 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\B79A7B0B31CF36361487D7CB6E7874132B056528D8AA4146424A7D1ECA72BC44.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_CL_2147888977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.CL"
        threat_id = "2147888977"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:B2F873769EB6B508EBC2103DDEB7366CEFB7B09AB8314DAD0C43461690726866" wide //weight: 1
        $x_1_2 = {42 32 46 38 37 33 37 36 39 45 42 36 42 35 30 38 45 42 43 32 31 30 33 44 44 45 42 37 33 36 36 43 45 46 42 37 42 30 39 41 42 38 33 31 34 44 41 44 30 43 34 33 34 36 31 36 39 30 37 32 36 38 36 36 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {42 32 46 38 37 33 37 36 39 45 42 36 42 35 30 38 45 42 43 32 31 30 33 44 44 45 42 37 33 36 36 43 45 46 42 37 42 30 39 41 42 38 33 31 34 44 41 44 30 43 34 33 34 36 31 36 39 30 37 32 36 38 36 36 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\B2F873769EB6B508EBC2103DDEB7366CEFB7B09AB8314DAD0C43461690726866.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_CM_2147889561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.CM"
        threat_id = "2147889561"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:FDF86CB226833382CE6C1C4A75C9F92BFD7CCA0F2AA6A890E0E67328B653FE20" wide //weight: 1
        $x_1_2 = {46 44 46 38 36 43 42 32 32 36 38 33 33 33 38 32 43 45 36 43 31 43 34 41 37 35 43 39 46 39 32 42 46 44 37 43 43 41 30 46 32 41 41 36 41 38 39 30 45 30 45 36 37 33 32 38 42 36 35 33 46 45 32 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {46 44 46 38 36 43 42 32 32 36 38 33 33 33 38 32 43 45 36 43 31 43 34 41 37 35 43 39 46 39 32 42 46 44 37 43 43 41 30 46 32 41 41 36 41 38 39 30 45 30 45 36 37 33 32 38 42 36 35 33 46 45 32 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\FDF86CB226833382CE6C1C4A75C9F92BFD7CCA0F2AA6A890E0E67328B653FE20.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_CN_2147890156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.CN"
        threat_id = "2147890156"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:777BB9F3522655CC91E0B48E256475A7633E12CCBF8C9EF2910413F9812CF416" wide //weight: 1
        $x_1_2 = {37 37 37 42 42 39 46 33 35 32 32 36 35 35 43 43 39 31 45 30 42 34 38 45 32 35 36 34 37 35 41 37 36 33 33 45 31 32 43 43 42 46 38 43 39 45 46 32 39 31 30 34 31 33 46 39 38 31 32 43 46 34 31 36 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {37 37 37 42 42 39 46 33 35 32 32 36 35 35 43 43 39 31 45 30 42 34 38 45 32 35 36 34 37 35 41 37 36 33 33 45 31 32 43 43 42 46 38 43 39 45 46 32 39 31 30 34 31 33 46 39 38 31 32 43 46 34 31 36 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\777BB9F3522655CC91E0B48E256475A7633E12CCBF8C9EF2910413F9812CF416.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_CO_2147890160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.CO"
        threat_id = "2147890160"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:69EB2511167FBE9E68546A93278FD52B7BA8F3F3529D5EEFBD63A513A2E73C3C" wide //weight: 1
        $x_1_2 = {36 39 45 42 32 35 31 31 31 36 37 46 42 45 39 45 36 38 35 34 36 41 39 33 32 37 38 46 44 35 32 42 37 42 41 38 46 33 46 33 35 32 39 44 35 45 45 46 42 44 36 33 41 35 31 33 41 32 45 37 33 43 33 43 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {36 39 45 42 32 35 31 31 31 36 37 46 42 45 39 45 36 38 35 34 36 41 39 33 32 37 38 46 44 35 32 42 37 42 41 38 46 33 46 33 35 32 39 44 35 45 45 46 42 44 36 33 41 35 31 33 41 32 45 37 33 43 33 43 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\69EB2511167FBE9E68546A93278FD52B7BA8F3F3529D5EEFBD63A513A2E73C3C.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_CP_2147890377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.CP"
        threat_id = "2147890377"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:B02838FD4FF823665F855FF713659B87186B9AD90C40F148977DC51352BDB43B" wide //weight: 1
        $x_1_2 = {42 30 32 38 33 38 46 44 34 46 46 38 32 33 36 36 35 46 38 35 35 46 46 37 31 33 36 35 39 42 38 37 31 38 36 42 39 41 44 39 30 43 34 30 46 31 34 38 39 37 37 44 43 35 31 33 35 32 42 44 42 34 33 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {42 30 32 38 33 38 46 44 34 46 46 38 32 33 36 36 35 46 38 35 35 46 46 37 31 33 36 35 39 42 38 37 31 38 36 42 39 41 44 39 30 43 34 30 46 31 34 38 39 37 37 44 43 35 31 33 35 32 42 44 42 34 33 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\B02838FD4FF823665F855FF713659B87186B9AD90C40F148977DC51352BDB43B.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_CQ_2147890381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.CQ"
        threat_id = "2147890381"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:2FFB95F4FDA76FBAD57BC1984F132304185BDF82DB42152B5E4E81D977B7E518" wide //weight: 1
        $x_1_2 = {32 46 46 42 39 35 46 34 46 44 41 37 36 46 42 41 44 35 37 42 43 31 39 38 34 46 31 33 32 33 30 34 31 38 35 42 44 46 38 32 44 42 34 32 31 35 32 42 35 45 34 45 38 31 44 39 37 37 42 37 45 35 31 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {32 46 46 42 39 35 46 34 46 44 41 37 36 46 42 41 44 35 37 42 43 31 39 38 34 46 31 33 32 33 30 34 31 38 35 42 44 46 38 32 44 42 34 32 31 35 32 42 35 45 34 45 38 31 44 39 37 37 42 37 45 35 31 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\2FFB95F4FDA76FBAD57BC1984F132304185BDF82DB42152B5E4E81D977B7E518.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_CR_2147890570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.CR"
        threat_id = "2147890570"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:BAED7AD40C392D20A6F6857912720B14E69CD01BB1D6E5C0B904EE4BE26E9D13" wide //weight: 1
        $x_1_2 = {42 41 45 44 37 41 44 34 30 43 33 39 32 44 32 30 41 36 46 36 38 35 37 39 31 32 37 32 30 42 31 34 45 36 39 43 44 30 31 42 42 31 44 36 45 35 43 30 42 39 30 34 45 45 34 42 45 32 36 45 39 44 31 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {42 41 45 44 37 41 44 34 30 43 33 39 32 44 32 30 41 36 46 36 38 35 37 39 31 32 37 32 30 42 31 34 45 36 39 43 44 30 31 42 42 31 44 36 45 35 43 30 42 39 30 34 45 45 34 42 45 32 36 45 39 44 31 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\BAED7AD40C392D20A6F6857912720B14E69CD01BB1D6E5C0B904EE4BE26E9D13.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_CS_2147890574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.CS"
        threat_id = "2147890574"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:9F653109E6CFA1890999C1C581500618005F6789D974FB67ED66B98ABF7D0732" wide //weight: 1
        $x_1_2 = {39 46 36 35 33 31 30 39 45 36 43 46 41 31 38 39 30 39 39 39 43 31 43 35 38 31 35 30 30 36 31 38 30 30 35 46 36 37 38 39 44 39 37 34 46 42 36 37 45 44 36 36 42 39 38 41 42 46 37 44 30 37 33 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {39 46 36 35 33 31 30 39 45 36 43 46 41 31 38 39 30 39 39 39 43 31 43 35 38 31 35 30 30 36 31 38 30 30 35 46 36 37 38 39 44 39 37 34 46 42 36 37 45 44 36 36 42 39 38 41 42 46 37 44 30 37 33 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\9F653109E6CFA1890999C1C581500618005F6789D974FB67ED66B98ABF7D0732.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_CT_2147891235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.CT"
        threat_id = "2147891235"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:5FEB774F4CF3A15FC392C3CC90313B964353D2CE9239B878F279BDF80B25CE57" wide //weight: 1
        $x_1_2 = {35 46 45 42 37 37 34 46 34 43 46 33 41 31 35 46 43 33 39 32 43 33 43 43 39 30 33 31 33 42 39 36 34 33 35 33 44 32 43 45 39 32 33 39 42 38 37 38 46 32 37 39 42 44 46 38 30 42 32 35 43 45 35 37 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {35 46 45 42 37 37 34 46 34 43 46 33 41 31 35 46 43 33 39 32 43 33 43 43 39 30 33 31 33 42 39 36 34 33 35 33 44 32 43 45 39 32 33 39 42 38 37 38 46 32 37 39 42 44 46 38 30 42 32 35 43 45 35 37 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\5FEB774F4CF3A15FC392C3CC90313B964353D2CE9239B878F279BDF80B25CE57.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_CU_2147891749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.CU"
        threat_id = "2147891749"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:30D1B4FAB9287E9C54969DB3F17A402A0BDFA9BCD45B3B2BDA5688EE879BA770" wide //weight: 1
        $x_1_2 = {33 30 44 31 42 34 46 41 42 39 32 38 37 45 39 43 35 34 39 36 39 44 42 33 46 31 37 41 34 30 32 41 30 42 44 46 41 39 42 43 44 34 35 42 33 42 32 42 44 41 35 36 38 38 45 45 38 37 39 42 41 37 37 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {33 30 44 31 42 34 46 41 42 39 32 38 37 45 39 43 35 34 39 36 39 44 42 33 46 31 37 41 34 30 32 41 30 42 44 46 41 39 42 43 44 34 35 42 33 42 32 42 44 41 35 36 38 38 45 45 38 37 39 42 41 37 37 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\30D1B4FAB9287E9C54969DB3F17A402A0BDFA9BCD45B3B2BDA5688EE879BA770.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_CV_2147891753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.CV"
        threat_id = "2147891753"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:68D93E04CD13FB660DBB8C6672183373C577AF957B78E7FEFFD561EFF7BD110C" wide //weight: 1
        $x_1_2 = {36 38 44 39 33 45 30 34 43 44 31 33 46 42 36 36 30 44 42 42 38 43 36 36 37 32 31 38 33 33 37 33 43 35 37 37 41 46 39 35 37 42 37 38 45 37 46 45 46 46 44 35 36 31 45 46 46 37 42 44 31 31 30 43 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {36 38 44 39 33 45 30 34 43 44 31 33 46 42 36 36 30 44 42 42 38 43 36 36 37 32 31 38 33 33 37 33 43 35 37 37 41 46 39 35 37 42 37 38 45 37 46 45 46 46 44 35 36 31 45 46 46 37 42 44 31 31 30 43 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\68D93E04CD13FB660DBB8C6672183373C577AF957B78E7FEFFD561EFF7BD110C.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_CW_2147891757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.CW"
        threat_id = "2147891757"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:C3CC4E254DEF87B28FD67818F5E446BB23C89B402FACA36B49C0EECFC75AA058" wide //weight: 1
        $x_1_2 = {43 33 43 43 34 45 32 35 34 44 45 46 38 37 42 32 38 46 44 36 37 38 31 38 46 35 45 34 34 36 42 42 32 33 43 38 39 42 34 30 32 46 41 43 41 33 36 42 34 39 43 30 45 45 43 46 43 37 35 41 41 30 35 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {43 33 43 43 34 45 32 35 34 44 45 46 38 37 42 32 38 46 44 36 37 38 31 38 46 35 45 34 34 36 42 42 32 33 43 38 39 42 34 30 32 46 41 43 41 33 36 42 34 39 43 30 45 45 43 46 43 37 35 41 41 30 35 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\C3CC4E254DEF87B28FD67818F5E446BB23C89B402FACA36B49C0EECFC75AA058.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_CX_2147891761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.CX"
        threat_id = "2147891761"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:09B950550CAD95899AC17C0B1384CD55C9BD81396B19EFFE2E80839D641D3221" wide //weight: 1
        $x_1_2 = {30 39 42 39 35 30 35 35 30 43 41 44 39 35 38 39 39 41 43 31 37 43 30 42 31 33 38 34 43 44 35 35 43 39 42 44 38 31 33 39 36 42 31 39 45 46 46 45 32 45 38 30 38 33 39 44 36 34 31 44 33 32 32 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {30 39 42 39 35 30 35 35 30 43 41 44 39 35 38 39 39 41 43 31 37 43 30 42 31 33 38 34 43 44 35 35 43 39 42 44 38 31 33 39 36 42 31 39 45 46 46 45 32 45 38 30 38 33 39 44 36 34 31 44 33 32 32 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\09B950550CAD95899AC17C0B1384CD55C9BD81396B19EFFE2E80839D641D3221.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_CY_2147892601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.CY"
        threat_id = "2147892601"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:0421BD35FA5A5849FB9BEB1595DBBE239DDE19B46B0B8BD73EDD1107C245B46C" wide //weight: 1
        $x_1_2 = {30 34 32 31 42 44 33 35 46 41 35 41 35 38 34 39 46 42 39 42 45 42 31 35 39 35 44 42 42 45 32 33 39 44 44 45 31 39 42 34 36 42 30 42 38 42 44 37 33 45 44 44 31 31 30 37 43 32 34 35 42 34 36 43 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {30 34 32 31 42 44 33 35 46 41 35 41 35 38 34 39 46 42 39 42 45 42 31 35 39 35 44 42 42 45 32 33 39 44 44 45 31 39 42 34 36 42 30 42 38 42 44 37 33 45 44 44 31 31 30 37 43 32 34 35 42 34 36 43 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\0421BD35FA5A5849FB9BEB1595DBBE239DDE19B46B0B8BD73EDD1107C245B46C.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_CZ_2147893020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.CZ"
        threat_id = "2147893020"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:BC3723356CBA89461914C536F047F0E66C20FBC4134FC5E46ABCEFF768D7DC1C" wide //weight: 1
        $x_1_2 = {42 43 33 37 32 33 33 35 36 43 42 41 38 39 34 36 31 39 31 34 43 35 33 36 46 30 34 37 46 30 45 36 36 43 32 30 46 42 43 34 31 33 34 46 43 35 45 34 36 41 42 43 45 46 46 37 36 38 44 37 44 43 31 43 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {42 43 33 37 32 33 33 35 36 43 42 41 38 39 34 36 31 39 31 34 43 35 33 36 46 30 34 37 46 30 45 36 36 43 32 30 46 42 43 34 31 33 34 46 43 35 45 34 36 41 42 43 45 46 46 37 36 38 44 37 44 43 31 43 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\BC3723356CBA89461914C536F047F0E66C20FBC4134FC5E46ABCEFF768D7DC1C.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_DA_2147893024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.DA"
        threat_id = "2147893024"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:D8E29F22B9582F1E7A180A28F0DD90627A1220DD7E90559450B9AAEA64669D0D" wide //weight: 1
        $x_1_2 = {44 38 45 32 39 46 32 32 42 39 35 38 32 46 31 45 37 41 31 38 30 41 32 38 46 30 44 44 39 30 36 32 37 41 31 32 32 30 44 44 37 45 39 30 35 35 39 34 35 30 42 39 41 41 45 41 36 34 36 36 39 44 30 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {44 38 45 32 39 46 32 32 42 39 35 38 32 46 31 45 37 41 31 38 30 41 32 38 46 30 44 44 39 30 36 32 37 41 31 32 32 30 44 44 37 45 39 30 35 35 39 34 35 30 42 39 41 41 45 41 36 34 36 36 39 44 30 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\D8E29F22B9582F1E7A180A28F0DD90627A1220DD7E90559450B9AAEA64669D0D.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_DB_2147893203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.DB"
        threat_id = "2147893203"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:5B85F0F52F989C42FE18A08351D4B9F50D7A9832DBE4A068346DE35D5CF8F410" wide //weight: 1
        $x_1_2 = {35 42 38 35 46 30 46 35 32 46 39 38 39 43 34 32 46 45 31 38 41 30 38 33 35 31 44 34 42 39 46 35 30 44 37 41 39 38 33 32 44 42 45 34 41 30 36 38 33 34 36 44 45 33 35 44 35 43 46 38 46 34 31 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {35 42 38 35 46 30 46 35 32 46 39 38 39 43 34 32 46 45 31 38 41 30 38 33 35 31 44 34 42 39 46 35 30 44 37 41 39 38 33 32 44 42 45 34 41 30 36 38 33 34 36 44 45 33 35 44 35 43 46 38 46 34 31 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\5B85F0F52F989C42FE18A08351D4B9F50D7A9832DBE4A068346DE35D5CF8F410.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_DC_2147893207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.DC"
        threat_id = "2147893207"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:37737C5A90A32D6417DC12A01CA6A5B8496F7AB1AAAC5CF89AD398B713A1163F" wide //weight: 1
        $x_1_2 = {33 37 37 33 37 43 35 41 39 30 41 33 32 44 36 34 31 37 44 43 31 32 41 30 31 43 41 36 41 35 42 38 34 39 36 46 37 41 42 31 41 41 41 43 35 43 46 38 39 41 44 33 39 38 42 37 31 33 41 31 31 36 33 46 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {33 37 37 33 37 43 35 41 39 30 41 33 32 44 36 34 31 37 44 43 31 32 41 30 31 43 41 36 41 35 42 38 34 39 36 46 37 41 42 31 41 41 41 43 35 43 46 38 39 41 44 33 39 38 42 37 31 33 41 31 31 36 33 46 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\37737C5A90A32D6417DC12A01CA6A5B8496F7AB1AAAC5CF89AD398B713A1163F.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_DD_2147893217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.DD"
        threat_id = "2147893217"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:B761680E23F2EBB5F6887D315EBD05B2D7C365731E093B49ADB059C3DCCAA30C" wide //weight: 1
        $x_1_2 = {42 37 36 31 36 38 30 45 32 33 46 32 45 42 42 35 46 36 38 38 37 44 33 31 35 45 42 44 30 35 42 32 44 37 43 33 36 35 37 33 31 45 30 39 33 42 34 39 41 44 42 30 35 39 43 33 44 43 43 41 41 33 30 43 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {42 37 36 31 36 38 30 45 32 33 46 32 45 42 42 35 46 36 38 38 37 44 33 31 35 45 42 44 30 35 42 32 44 37 43 33 36 35 37 33 31 45 30 39 33 42 34 39 41 44 42 30 35 39 43 33 44 43 43 41 41 33 30 43 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\B761680E23F2EBB5F6887D315EBD05B2D7C365731E093B49ADB059C3DCCAA30C.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_DE_2147893278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.DE"
        threat_id = "2147893278"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:0371CD54F80CBB490ED8E14001F82D6AC9C7FA298E7DB38F6F645028C96AA561" wide //weight: 1
        $x_1_2 = {30 33 37 31 43 44 35 34 46 38 30 43 42 42 34 39 30 45 44 38 45 31 34 30 30 31 46 38 32 44 36 41 43 39 43 37 46 41 32 39 38 45 37 44 42 33 38 46 36 46 36 34 35 30 32 38 43 39 36 41 41 35 36 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {30 33 37 31 43 44 35 34 46 38 30 43 42 42 34 39 30 45 44 38 45 31 34 30 30 31 46 38 32 44 36 41 43 39 43 37 46 41 32 39 38 45 37 44 42 33 38 46 36 46 36 34 35 30 32 38 43 39 36 41 41 35 36 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\0371CD54F80CBB490ED8E14001F82D6AC9C7FA298E7DB38F6F645028C96AA561.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_DF_2147893531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.DF"
        threat_id = "2147893531"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:8F804D66441DF4A210CF43C1B9C074823C7A8D1AE3ACF3215F7EC303717A0E42" wide //weight: 1
        $x_1_2 = {38 46 38 30 34 44 36 36 34 34 31 44 46 34 41 32 31 30 43 46 34 33 43 31 42 39 43 30 37 34 38 32 33 43 37 41 38 44 31 41 45 33 41 43 46 33 32 31 35 46 37 45 43 33 30 33 37 31 37 41 30 45 34 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {38 46 38 30 34 44 36 36 34 34 31 44 46 34 41 32 31 30 43 46 34 33 43 31 42 39 43 30 37 34 38 32 33 43 37 41 38 44 31 41 45 33 41 43 46 33 32 31 35 46 37 45 43 33 30 33 37 31 37 41 30 45 34 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\8F804D66441DF4A210CF43C1B9C074823C7A8D1AE3ACF3215F7EC303717A0E42.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_DG_2147893978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.DG"
        threat_id = "2147893978"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:E21185C273FF3BBAF0522224502D79EAFBC91DAA3F6167DA771E86B49DD0F238" wide //weight: 1
        $x_1_2 = {45 32 31 31 38 35 43 32 37 33 46 46 33 42 42 41 46 30 35 32 32 32 32 34 35 30 32 44 37 39 45 41 46 42 43 39 31 44 41 41 33 46 36 31 36 37 44 41 37 37 31 45 38 36 42 34 39 44 44 30 46 32 33 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {45 32 31 31 38 35 43 32 37 33 46 46 33 42 42 41 46 30 35 32 32 32 32 34 35 30 32 44 37 39 45 41 46 42 43 39 31 44 41 41 33 46 36 31 36 37 44 41 37 37 31 45 38 36 42 34 39 44 44 30 46 32 33 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\E21185C273FF3BBAF0522224502D79EAFBC91DAA3F6167DA771E86B49DD0F238.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_DH_2147893982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.DH"
        threat_id = "2147893982"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:461E4844E177B98FA19053599289ECCCA128D319E725152FCA5A040A5D22A122" wide //weight: 1
        $x_1_2 = {34 36 31 45 34 38 34 34 45 31 37 37 42 39 38 46 41 31 39 30 35 33 35 39 39 32 38 39 45 43 43 43 41 31 32 38 44 33 31 39 45 37 32 35 31 35 32 46 43 41 35 41 30 34 30 41 35 44 32 32 41 31 32 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {34 36 31 45 34 38 34 34 45 31 37 37 42 39 38 46 41 31 39 30 35 33 35 39 39 32 38 39 45 43 43 43 41 31 32 38 44 33 31 39 45 37 32 35 31 35 32 46 43 41 35 41 30 34 30 41 35 44 32 32 41 31 32 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\461E4844E177B98FA19053599289ECCCA128D319E725152FCA5A040A5D22A122.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_DI_2147895123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.DI"
        threat_id = "2147895123"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:F1D0F45DBC3F4CA784D5D0D0DD8ADCD31AB5645BE00293FE6302CD0381F6527A" wide //weight: 1
        $x_1_2 = {46 31 44 30 46 34 35 44 42 43 33 46 34 43 41 37 38 34 44 35 44 30 44 30 44 44 38 41 44 43 44 33 31 41 42 35 36 34 35 42 45 30 30 32 39 33 46 45 36 33 30 32 43 44 30 33 38 31 46 36 35 32 37 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {46 31 44 30 46 34 35 44 42 43 33 46 34 43 41 37 38 34 44 35 44 30 44 30 44 44 38 41 44 43 44 33 31 41 42 35 36 34 35 42 45 30 30 32 39 33 46 45 36 33 30 32 43 44 30 33 38 31 46 36 35 32 37 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\F1D0F45DBC3F4CA784D5D0D0DD8ADCD31AB5645BE00293FE6302CD0381F6527A.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_DJ_2147895143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.DJ"
        threat_id = "2147895143"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:49D46141AF71989E7986FEE3A3417058AB55A63F3A27FB8094148248F4899A10" wide //weight: 1
        $x_1_2 = {34 39 44 34 36 31 34 31 41 46 37 31 39 38 39 45 37 39 38 36 46 45 45 33 41 33 34 31 37 30 35 38 41 42 35 35 41 36 33 46 33 41 32 37 46 42 38 30 39 34 31 34 38 32 34 38 46 34 38 39 39 41 31 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {34 39 44 34 36 31 34 31 41 46 37 31 39 38 39 45 37 39 38 36 46 45 45 33 41 33 34 31 37 30 35 38 41 42 35 35 41 36 33 46 33 41 32 37 46 42 38 30 39 34 31 34 38 32 34 38 46 34 38 39 39 41 31 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\49D46141AF71989E7986FEE3A3417058AB55A63F3A27FB8094148248F4899A10.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_DK_2147895507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.DK"
        threat_id = "2147895507"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:657CB615E462F4D82AA8A0EACE0EAA9B9F0C0E168898585B638569608226441C" wide //weight: 1
        $x_1_2 = {36 35 37 43 42 36 31 35 45 34 36 32 46 34 44 38 32 41 41 38 41 30 45 41 43 45 30 45 41 41 39 42 39 46 30 43 30 45 31 36 38 38 39 38 35 38 35 42 36 33 38 35 36 39 36 30 38 32 32 36 34 34 31 43 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {36 35 37 43 42 36 31 35 45 34 36 32 46 34 44 38 32 41 41 38 41 30 45 41 43 45 30 45 41 41 39 42 39 46 30 43 30 45 31 36 38 38 39 38 35 38 35 42 36 33 38 35 36 39 36 30 38 32 32 36 34 34 31 43 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\657CB615E462F4D82AA8A0EACE0EAA9B9F0C0E168898585B638569608226441C.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_DL_2147895692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.DL"
        threat_id = "2147895692"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:C589F5D0AF2DF14EAFF5DAA494C8FB59F14D320BB31CF65E8D2BE4C8B98E764A" wide //weight: 1
        $x_1_2 = {43 35 38 39 46 35 44 30 41 46 32 44 46 31 34 45 41 46 46 35 44 41 41 34 39 34 43 38 46 42 35 39 46 31 34 44 33 32 30 42 42 33 31 43 46 36 35 45 38 44 32 42 45 34 43 38 42 39 38 45 37 36 34 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {43 35 38 39 46 35 44 30 41 46 32 44 46 31 34 45 41 46 46 35 44 41 41 34 39 34 43 38 46 42 35 39 46 31 34 44 33 32 30 42 42 33 31 43 46 36 35 45 38 44 32 42 45 34 43 38 42 39 38 45 37 36 34 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\C589F5D0AF2DF14EAFF5DAA494C8FB59F14D320BB31CF65E8D2BE4C8B98E764A.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_DM_2147896587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.DM"
        threat_id = "2147896587"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:B2DECD2A54DD80C0E48ABB0F98A5A09E71393A303AD4B2AEF8498CA6C9EEE628" wide //weight: 1
        $x_1_2 = {42 32 44 45 43 44 32 41 35 34 44 44 38 30 43 30 45 34 38 41 42 42 30 46 39 38 41 35 41 30 39 45 37 31 33 39 33 41 33 30 33 41 44 34 42 32 41 45 46 38 34 39 38 43 41 36 43 39 45 45 45 36 32 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {42 32 44 45 43 44 32 41 35 34 44 44 38 30 43 30 45 34 38 41 42 42 30 46 39 38 41 35 41 30 39 45 37 31 33 39 33 41 33 30 33 41 44 34 42 32 41 45 46 38 34 39 38 43 41 36 43 39 45 45 45 36 32 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\B2DECD2A54DD80C0E48ABB0F98A5A09E71393A303AD4B2AEF8498CA6C9EEE628.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_DN_2147896591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.DN"
        threat_id = "2147896591"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:DE9F011510DD644D626456BE395A8A5857CB669F1982AC3A954575CA7E35E100" wide //weight: 1
        $x_1_2 = {44 45 39 46 30 31 31 35 31 30 44 44 36 34 34 44 36 32 36 34 35 36 42 45 33 39 35 41 38 41 35 38 35 37 43 42 36 36 39 46 31 39 38 32 41 43 33 41 39 35 34 35 37 35 43 41 37 45 33 35 45 31 30 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {44 45 39 46 30 31 31 35 31 30 44 44 36 34 34 44 36 32 36 34 35 36 42 45 33 39 35 41 38 41 35 38 35 37 43 42 36 36 39 46 31 39 38 32 41 43 33 41 39 35 34 35 37 35 43 41 37 45 33 35 45 31 30 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\DE9F011510DD644D626456BE395A8A5857CB669F1982AC3A954575CA7E35E100.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_DO_2147896595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.DO"
        threat_id = "2147896595"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:2AECDEAAF9C4EBECAF787C971DC882E5270CBCB23E646027B814FAA60607CF6E" wide //weight: 1
        $x_1_2 = {32 41 45 43 44 45 41 41 46 39 43 34 45 42 45 43 41 46 37 38 37 43 39 37 31 44 43 38 38 32 45 35 32 37 30 43 42 43 42 32 33 45 36 34 36 30 32 37 42 38 31 34 46 41 41 36 30 36 30 37 43 46 36 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {32 41 45 43 44 45 41 41 46 39 43 34 45 42 45 43 41 46 37 38 37 43 39 37 31 44 43 38 38 32 45 35 32 37 30 43 42 43 42 32 33 45 36 34 36 30 32 37 42 38 31 34 46 41 41 36 30 36 30 37 43 46 36 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\2AECDEAAF9C4EBECAF787C971DC882E5270CBCB23E646027B814FAA60607CF6E.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_DP_2147896599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.DP"
        threat_id = "2147896599"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:12628E802B0C063E33AAB49BF53A41755CF00422723B0C122F1108A2B8436F54" wide //weight: 1
        $x_1_2 = {31 32 36 32 38 45 38 30 32 42 30 43 30 36 33 45 33 33 41 41 42 34 39 42 46 35 33 41 34 31 37 35 35 43 46 30 30 34 32 32 37 32 33 42 30 43 31 32 32 46 31 31 30 38 41 32 42 38 34 33 36 46 35 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {31 32 36 32 38 45 38 30 32 42 30 43 30 36 33 45 33 33 41 41 42 34 39 42 46 35 33 41 34 31 37 35 35 43 46 30 30 34 32 32 37 32 33 42 30 43 31 32 32 46 31 31 30 38 41 32 42 38 34 33 36 46 35 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\12628E802B0C063E33AAB49BF53A41755CF00422723B0C122F1108A2B8436F54.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_DQ_2147897106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.DQ"
        threat_id = "2147897106"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:2731CB3EA9E8A1F2822C3D0DD5A7FD9955DE0C99E77A05C246D42E301D93A648" wide //weight: 1
        $x_1_2 = {32 37 33 31 43 42 33 45 41 39 45 38 41 31 46 32 38 32 32 43 33 44 30 44 44 35 41 37 46 44 39 39 35 35 44 45 30 43 39 39 45 37 37 41 30 35 43 32 34 36 44 34 32 45 33 30 31 44 39 33 41 36 34 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {32 37 33 31 43 42 33 45 41 39 45 38 41 31 46 32 38 32 32 43 33 44 30 44 44 35 41 37 46 44 39 39 35 35 44 45 30 43 39 39 45 37 37 41 30 35 43 32 34 36 44 34 32 45 33 30 31 44 39 33 41 36 34 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\2731CB3EA9E8A1F2822C3D0DD5A7FD9955DE0C99E77A05C246D42E301D93A648.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_DR_2147897110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.DR"
        threat_id = "2147897110"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:A72D3895FF672D121212CBAE9B17A23504DFCC4443C835057BB9FC128A7F9023" wide //weight: 1
        $x_1_2 = {41 37 32 44 33 38 39 35 46 46 36 37 32 44 31 32 31 32 31 32 43 42 41 45 39 42 31 37 41 32 33 35 30 34 44 46 43 43 34 34 34 33 43 38 33 35 30 35 37 42 42 39 46 43 31 32 38 41 37 46 39 30 32 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {41 37 32 44 33 38 39 35 46 46 36 37 32 44 31 32 31 32 31 32 43 42 41 45 39 42 31 37 41 32 33 35 30 34 44 46 43 43 34 34 34 33 43 38 33 35 30 35 37 42 42 39 46 43 31 32 38 41 37 46 39 30 32 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\A72D3895FF672D121212CBAE9B17A23504DFCC4443C835057BB9FC128A7F9023.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_DS_2147897114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.DS"
        threat_id = "2147897114"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:E13442A06BED50DC366E0EACEDD493BBF4DEC090ACF31A702E3EEFE15FCB225D" wide //weight: 1
        $x_1_2 = {45 31 33 34 34 32 41 30 36 42 45 44 35 30 44 43 33 36 36 45 30 45 41 43 45 44 44 34 39 33 42 42 46 34 44 45 43 30 39 30 41 43 46 33 31 41 37 30 32 45 33 45 45 46 45 31 35 46 43 42 32 32 35 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {45 31 33 34 34 32 41 30 36 42 45 44 35 30 44 43 33 36 36 45 30 45 41 43 45 44 44 34 39 33 42 42 46 34 44 45 43 30 39 30 41 43 46 33 31 41 37 30 32 45 33 45 45 46 45 31 35 46 43 42 32 32 35 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\E13442A06BED50DC366E0EACEDD493BBF4DEC090ACF31A702E3EEFE15FCB225D.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_DT_2147897221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.DT"
        threat_id = "2147897221"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:AA47F8CA532A6D71528143A4F9A3016E1BA07E155FE41DEBBEA94E2B2ED8546A" wide //weight: 1
        $x_1_2 = {41 41 34 37 46 38 43 41 35 33 32 41 36 44 37 31 35 32 38 31 34 33 41 34 46 39 41 33 30 31 36 45 31 42 41 30 37 45 31 35 35 46 45 34 31 44 45 42 42 45 41 39 34 45 32 42 32 45 44 38 35 34 36 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {41 41 34 37 46 38 43 41 35 33 32 41 36 44 37 31 35 32 38 31 34 33 41 34 46 39 41 33 30 31 36 45 31 42 41 30 37 45 31 35 35 46 45 34 31 44 45 42 42 45 41 39 34 45 32 42 32 45 44 38 35 34 36 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\AA47F8CA532A6D71528143A4F9A3016E1BA07E155FE41DEBBEA94E2B2ED8546A.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_DU_2147898499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.DU"
        threat_id = "2147898499"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:A2BE792BBE8077482156DC950840EA5F1CB0F8AB1C403BF6DDF863489C7CC60E" wide //weight: 1
        $x_1_2 = {41 32 42 45 37 39 32 42 42 45 38 30 37 37 34 38 32 31 35 36 44 43 39 35 30 38 34 30 45 41 35 46 31 43 42 30 46 38 41 42 31 43 34 30 33 42 46 36 44 44 46 38 36 33 34 38 39 43 37 43 43 36 30 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {41 32 42 45 37 39 32 42 42 45 38 30 37 37 34 38 32 31 35 36 44 43 39 35 30 38 34 30 45 41 35 46 31 43 42 30 46 38 41 42 31 43 34 30 33 42 46 36 44 44 46 38 36 33 34 38 39 43 37 43 43 36 30 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\A2BE792BBE8077482156DC950840EA5F1CB0F8AB1C403BF6DDF863489C7CC60E.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_DV_2147898503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.DV"
        threat_id = "2147898503"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:E24F024A739BF4CC1A40FD970A11154D231FB5DF0D401C17E4C2439AA7903463" wide //weight: 1
        $x_1_2 = {45 32 34 46 30 32 34 41 37 33 39 42 46 34 43 43 31 41 34 30 46 44 39 37 30 41 31 31 31 35 34 44 32 33 31 46 42 35 44 46 30 44 34 30 31 43 31 37 45 34 43 32 34 33 39 41 41 37 39 30 33 34 36 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {45 32 34 46 30 32 34 41 37 33 39 42 46 34 43 43 31 41 34 30 46 44 39 37 30 41 31 31 31 35 34 44 32 33 31 46 42 35 44 46 30 44 34 30 31 43 31 37 45 34 43 32 34 33 39 41 41 37 39 30 33 34 36 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\E24F024A739BF4CC1A40FD970A11154D231FB5DF0D401C17E4C2439AA7903463.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_DW_2147898507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.DW"
        threat_id = "2147898507"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:AD529139F9C08CECFF34C92A6D4D03324B8CD450BC0BEEDC071297BBCB596E59" wide //weight: 1
        $x_1_2 = {41 44 35 32 39 31 33 39 46 39 43 30 38 43 45 43 46 46 33 34 43 39 32 41 36 44 34 44 30 33 33 32 34 42 38 43 44 34 35 30 42 43 30 42 45 45 44 43 30 37 31 32 39 37 42 42 43 42 35 39 36 45 35 39 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {41 44 35 32 39 31 33 39 46 39 43 30 38 43 45 43 46 46 33 34 43 39 32 41 36 44 34 44 30 33 33 32 34 42 38 43 44 34 35 30 42 43 30 42 45 45 44 43 30 37 31 32 39 37 42 42 43 42 35 39 36 45 35 39 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\AD529139F9C08CECFF34C92A6D4D03324B8CD450BC0BEEDC071297BBCB596E59.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_DX_2147898511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.DX"
        threat_id = "2147898511"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:90AD660309EDF9786F15C85EE20F7BBEB82A4D727A0B619E9FE791F5CA049E09" wide //weight: 1
        $x_1_2 = {39 30 41 44 36 36 30 33 30 39 45 44 46 39 37 38 36 46 31 35 43 38 35 45 45 32 30 46 37 42 42 45 42 38 32 41 34 44 37 32 37 41 30 42 36 31 39 45 39 46 45 37 39 31 46 35 43 41 30 34 39 45 30 39 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {39 30 41 44 36 36 30 33 30 39 45 44 46 39 37 38 36 46 31 35 43 38 35 45 45 32 30 46 37 42 42 45 42 38 32 41 34 44 37 32 37 41 30 42 36 31 39 45 39 46 45 37 39 31 46 35 43 41 30 34 39 45 30 39 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\90AD660309EDF9786F15C85EE20F7BBEB82A4D727A0B619E9FE791F5CA049E09.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_DY_2147898515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.DY"
        threat_id = "2147898515"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:7FEBE7DA5E3FADF691ABC60DE0F15D4EEC0BF089845487631594822F4F516222" wide //weight: 1
        $x_1_2 = {37 46 45 42 45 37 44 41 35 45 33 46 41 44 46 36 39 31 41 42 43 36 30 44 45 30 46 31 35 44 34 45 45 43 30 42 46 30 38 39 38 34 35 34 38 37 36 33 31 35 39 34 38 32 32 46 34 46 35 31 36 32 32 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {37 46 45 42 45 37 44 41 35 45 33 46 41 44 46 36 39 31 41 42 43 36 30 44 45 30 46 31 35 44 34 45 45 43 30 42 46 30 38 39 38 34 35 34 38 37 36 33 31 35 39 34 38 32 32 46 34 46 35 31 36 32 32 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\7FEBE7DA5E3FADF691ABC60DE0F15D4EEC0BF089845487631594822F4F516222.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_DZ_2147898519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.DZ"
        threat_id = "2147898519"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:B7A49CA7FF4A5DFE23DD437A9C81C430831AE0FE99B389E6A2991BC38915B272" wide //weight: 1
        $x_1_2 = {42 37 41 34 39 43 41 37 46 46 34 41 35 44 46 45 32 33 44 44 34 33 37 41 39 43 38 31 43 34 33 30 38 33 31 41 45 30 46 45 39 39 42 33 38 39 45 36 41 32 39 39 31 42 43 33 38 39 31 35 42 32 37 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {42 37 41 34 39 43 41 37 46 46 34 41 35 44 46 45 32 33 44 44 34 33 37 41 39 43 38 31 43 34 33 30 38 33 31 41 45 30 46 45 39 39 42 33 38 39 45 36 41 32 39 39 31 42 43 33 38 39 31 35 42 32 37 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\B7A49CA7FF4A5DFE23DD437A9C81C430831AE0FE99B389E6A2991BC38915B272.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_EA_2147898523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.EA"
        threat_id = "2147898523"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:0BF0BA66030916F61BB7D9E954FB98A8F973DB6531F18EB6CEE006D7E275B906" wide //weight: 1
        $x_1_2 = {30 42 46 30 42 41 36 36 30 33 30 39 31 36 46 36 31 42 42 37 44 39 45 39 35 34 46 42 39 38 41 38 46 39 37 33 44 42 36 35 33 31 46 31 38 45 42 36 43 45 45 30 30 36 44 37 45 32 37 35 42 39 30 36 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {30 42 46 30 42 41 36 36 30 33 30 39 31 36 46 36 31 42 42 37 44 39 45 39 35 34 46 42 39 38 41 38 46 39 37 33 44 42 36 35 33 31 46 31 38 45 42 36 43 45 45 30 30 36 44 37 45 32 37 35 42 39 30 36 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\0BF0BA66030916F61BB7D9E954FB98A8F973DB6531F18EB6CEE006D7E275B906.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_EB_2147898527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.EB"
        threat_id = "2147898527"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:7CB85C41D6E3FC9602FB8D79B955820AC4EEF41F29F2177B9750C129935F216F" wide //weight: 1
        $x_1_2 = {37 43 42 38 35 43 34 31 44 36 45 33 46 43 39 36 30 32 46 42 38 44 37 39 42 39 35 35 38 32 30 41 43 34 45 45 46 34 31 46 32 39 46 32 31 37 37 42 39 37 35 30 43 31 32 39 39 33 35 46 32 31 36 46 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {37 43 42 38 35 43 34 31 44 36 45 33 46 43 39 36 30 32 46 42 38 44 37 39 42 39 35 35 38 32 30 41 43 34 45 45 46 34 31 46 32 39 46 32 31 37 37 42 39 37 35 30 43 31 32 39 39 33 35 46 32 31 36 46 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\7CB85C41D6E3FC9602FB8D79B955820AC4EEF41F29F2177B9750C129935F216F.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_EC_2147898731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.EC"
        threat_id = "2147898731"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:D27A7B3711CD1442A8FAC19BB5780FF291101F6286A62AD21E5F7F08BD5F5F1B" wide //weight: 1
        $x_1_2 = {44 32 37 41 37 42 33 37 31 31 43 44 31 34 34 32 41 38 46 41 43 31 39 42 42 35 37 38 30 46 46 32 39 31 31 30 31 46 36 32 38 36 41 36 32 41 44 32 31 45 35 46 37 46 30 38 42 44 35 46 35 46 31 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {44 32 37 41 37 42 33 37 31 31 43 44 31 34 34 32 41 38 46 41 43 31 39 42 42 35 37 38 30 46 46 32 39 31 31 30 31 46 36 32 38 36 41 36 32 41 44 32 31 45 35 46 37 46 30 38 42 44 35 46 35 46 31 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\D27A7B3711CD1442A8FAC19BB5780FF291101F6286A62AD21E5F7F08BD5F5F1B.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_ED_2147898735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.ED"
        threat_id = "2147898735"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:7DFFA421CF18F77F3BB974A27646DE9DD985C1943584B48433BEB4A96F118621" wide //weight: 1
        $x_1_2 = {37 44 46 46 41 34 32 31 43 46 31 38 46 37 37 46 33 42 42 39 37 34 41 32 37 36 34 36 44 45 39 44 44 39 38 35 43 31 39 34 33 35 38 34 42 34 38 34 33 33 42 45 42 34 41 39 36 46 31 31 38 36 32 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {37 44 46 46 41 34 32 31 43 46 31 38 46 37 37 46 33 42 42 39 37 34 41 32 37 36 34 36 44 45 39 44 44 39 38 35 43 31 39 34 33 35 38 34 42 34 38 34 33 33 42 45 42 34 41 39 36 46 31 31 38 36 32 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\7DFFA421CF18F77F3BB974A27646DE9DD985C1943584B48433BEB4A96F118621.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_EE_2147899152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.EE"
        threat_id = "2147899152"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:02C75E60211314F4A69C323A3CE334D75C72CD8C742F3ED168447405C541DF05" wide //weight: 1
        $x_1_2 = {30 32 43 37 35 45 36 30 32 31 31 33 31 34 46 34 41 36 39 43 33 32 33 41 33 43 45 33 33 34 44 37 35 43 37 32 43 44 38 43 37 34 32 46 33 45 44 31 36 38 34 34 37 34 30 35 43 35 34 31 44 46 30 35 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {30 32 43 37 35 45 36 30 32 31 31 33 31 34 46 34 41 36 39 43 33 32 33 41 33 43 45 33 33 34 44 37 35 43 37 32 43 44 38 43 37 34 32 46 33 45 44 31 36 38 34 34 37 34 30 35 43 35 34 31 44 46 30 35 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\02C75E60211314F4A69C323A3CE334D75C72CD8C742F3ED168447405C541DF05.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_EF_2147900279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.EF"
        threat_id = "2147900279"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:1C054B722BCBF41A918EF3C485712742088F5C3E81B2FDD91ADEA6BA55F4A856" wide //weight: 1
        $x_1_2 = {31 43 30 35 34 42 37 32 32 42 43 42 46 34 31 41 39 31 38 45 46 33 43 34 38 35 37 31 32 37 34 32 30 38 38 46 35 43 33 45 38 31 42 32 46 44 44 39 31 41 44 45 41 36 42 41 35 35 46 34 41 38 35 36 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {31 43 30 35 34 42 37 32 32 42 43 42 46 34 31 41 39 31 38 45 46 33 43 34 38 35 37 31 32 37 34 32 30 38 38 46 35 43 33 45 38 31 42 32 46 44 44 39 31 41 44 45 41 36 42 41 35 35 46 34 41 38 35 36 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\1C054B722BCBF41A918EF3C485712742088F5C3E81B2FDD91ADEA6BA55F4A856.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_EG_2147900283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.EG"
        threat_id = "2147900283"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:A6FA4856508F2198468A7FCB4F194D7B52BE632364D81CCE6F4DAD6FABBF3A49" wide //weight: 1
        $x_1_2 = {41 36 46 41 34 38 35 36 35 30 38 46 32 31 39 38 34 36 38 41 37 46 43 42 34 46 31 39 34 44 37 42 35 32 42 45 36 33 32 33 36 34 44 38 31 43 43 45 36 46 34 44 41 44 36 46 41 42 42 46 33 41 34 39 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {41 36 46 41 34 38 35 36 35 30 38 46 32 31 39 38 34 36 38 41 37 46 43 42 34 46 31 39 34 44 37 42 35 32 42 45 36 33 32 33 36 34 44 38 31 43 43 45 36 46 34 44 41 44 36 46 41 42 42 46 33 41 34 39 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\A6FA4856508F2198468A7FCB4F194D7B52BE632364D81CCE6F4DAD6FABBF3A49.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_EH_2147902726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.EH"
        threat_id = "2147902726"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:98D120C9033653042E290627914B890A3291013F7377A976A028051C52440C71" wide //weight: 1
        $x_1_2 = {39 38 44 31 32 30 43 39 30 33 33 36 35 33 30 34 32 45 32 39 30 36 32 37 39 31 34 42 38 39 30 41 33 32 39 31 30 31 33 46 37 33 37 37 41 39 37 36 41 30 32 38 30 35 31 43 35 32 34 34 30 43 37 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {39 38 44 31 32 30 43 39 30 33 33 36 35 33 30 34 32 45 32 39 30 36 32 37 39 31 34 42 38 39 30 41 33 32 39 31 30 31 33 46 37 33 37 37 41 39 37 36 41 30 32 38 30 35 31 43 35 32 34 34 30 43 37 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\98D120C9033653042E290627914B890A3291013F7377A976A028051C52440C71.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_EI_2147903397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.EI"
        threat_id = "2147903397"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:59052DE8288FE054576FB2D8ADE27E35AD9269F5AB4BED99BDC019B81D40B97C" wide //weight: 1
        $x_1_2 = {35 39 30 35 32 44 45 38 32 38 38 46 45 30 35 34 35 37 36 46 42 32 44 38 41 44 45 32 37 45 33 35 41 44 39 32 36 39 46 35 41 42 34 42 45 44 39 39 42 44 43 30 31 39 42 38 31 44 34 30 42 39 37 43 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {35 39 30 35 32 44 45 38 32 38 38 46 45 30 35 34 35 37 36 46 42 32 44 38 41 44 45 32 37 45 33 35 41 44 39 32 36 39 46 35 41 42 34 42 45 44 39 39 42 44 43 30 31 39 42 38 31 44 34 30 42 39 37 43 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\59052DE8288FE054576FB2D8ADE27E35AD9269F5AB4BED99BDC019B81D40B97C.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_EJ_2147903950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.EJ"
        threat_id = "2147903950"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:E5BBFAD2DB3FB497EA03612B2428F927FD8A9B3333D524FD51D43B029B787057" wide //weight: 1
        $x_1_2 = {45 35 42 42 46 41 44 32 44 42 33 46 42 34 39 37 45 41 30 33 36 31 32 42 32 34 32 38 46 39 32 37 46 44 38 41 39 42 33 33 33 33 44 35 32 34 46 44 35 31 44 34 33 42 30 32 39 42 37 38 37 30 35 37 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {45 35 42 42 46 41 44 32 44 42 33 46 42 34 39 37 45 41 30 33 36 31 32 42 32 34 32 38 46 39 32 37 46 44 38 41 39 42 33 33 33 33 44 35 32 34 46 44 35 31 44 34 33 42 30 32 39 42 37 38 37 30 35 37 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\E5BBFAD2DB3FB497EA03612B2428F927FD8A9B3333D524FD51D43B029B787057.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_EK_2147904884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.EK"
        threat_id = "2147904884"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:ECBFA0EB44135FDB09BDE1F5EE8F95CE3F1009385CCA2FF3FEF4CB09C15BA854" wide //weight: 1
        $x_1_2 = {45 43 42 46 41 30 45 42 34 34 31 33 35 46 44 42 30 39 42 44 45 31 46 35 45 45 38 46 39 35 43 45 33 46 31 30 30 39 33 38 35 43 43 41 32 46 46 33 46 45 46 34 43 42 30 39 43 31 35 42 41 38 35 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {45 43 42 46 41 30 45 42 34 34 31 33 35 46 44 42 30 39 42 44 45 31 46 35 45 45 38 46 39 35 43 45 33 46 31 30 30 39 33 38 35 43 43 41 32 46 46 33 46 45 46 34 43 42 30 39 43 31 35 42 41 38 35 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\ECBFA0EB44135FDB09BDE1F5EE8F95CE3F1009385CCA2FF3FEF4CB09C15BA854.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_EL_2147905296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.EL"
        threat_id = "2147905296"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:B29F3EB9D89D940BFB8293B67977B9A24F74E2EDCF854AE7376D1BCE2BC85B70" wide //weight: 1
        $x_1_2 = {42 32 39 46 33 45 42 39 44 38 39 44 39 34 30 42 46 42 38 32 39 33 42 36 37 39 37 37 42 39 41 32 34 46 37 34 45 32 45 44 43 46 38 35 34 41 45 37 33 37 36 44 31 42 43 45 32 42 43 38 35 42 37 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {42 32 39 46 33 45 42 39 44 38 39 44 39 34 30 42 46 42 38 32 39 33 42 36 37 39 37 37 42 39 41 32 34 46 37 34 45 32 45 44 43 46 38 35 34 41 45 37 33 37 36 44 31 42 43 45 32 42 43 38 35 42 37 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\B29F3EB9D89D940BFB8293B67977B9A24F74E2EDCF854AE7376D1BCE2BC85B70.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_EM_2147905300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.EM"
        threat_id = "2147905300"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:4D598799696AD5399FABF7D40C4D1BE9F05D74CFB311047D7391AC0BF64BED47" wide //weight: 1
        $x_1_2 = {34 44 35 39 38 37 39 39 36 39 36 41 44 35 33 39 39 46 41 42 46 37 44 34 30 43 34 44 31 42 45 39 46 30 35 44 37 34 43 46 42 33 31 31 30 34 37 44 37 33 39 31 41 43 30 42 46 36 34 42 45 44 34 37 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {34 44 35 39 38 37 39 39 36 39 36 41 44 35 33 39 39 46 41 42 46 37 44 34 30 43 34 44 31 42 45 39 46 30 35 44 37 34 43 46 42 33 31 31 30 34 37 44 37 33 39 31 41 43 30 42 46 36 34 42 45 44 34 37 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\4D598799696AD5399FABF7D40C4D1BE9F05D74CFB311047D7391AC0BF64BED47.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_EN_2147905304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.EN"
        threat_id = "2147905304"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:5596A55062A4232F5AA55C2F7C4DF0AC1EAD10B78D4055A3328AD142A42B555E" wide //weight: 1
        $x_1_2 = {35 35 39 36 41 35 35 30 36 32 41 34 32 33 32 46 35 41 41 35 35 43 32 46 37 43 34 44 46 30 41 43 31 45 41 44 31 30 42 37 38 44 34 30 35 35 41 33 33 32 38 41 44 31 34 32 41 34 32 42 35 35 35 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {35 35 39 36 41 35 35 30 36 32 41 34 32 33 32 46 35 41 41 35 35 43 32 46 37 43 34 44 46 30 41 43 31 45 41 44 31 30 42 37 38 44 34 30 35 35 41 33 33 32 38 41 44 31 34 32 41 34 32 42 35 35 35 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\5596A55062A4232F5AA55C2F7C4DF0AC1EAD10B78D4055A3328AD142A42B555E.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_EO_2147905567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.EO"
        threat_id = "2147905567"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:6520A79F5A832F9D4238C2C2841D89A3246F7EF2B0185C735267D7D41F5D9129" wide //weight: 1
        $x_1_2 = {36 35 32 30 41 37 39 46 35 41 38 33 32 46 39 44 34 32 33 38 43 32 43 32 38 34 31 44 38 39 41 33 32 34 36 46 37 45 46 32 42 30 31 38 35 43 37 33 35 32 36 37 44 37 44 34 31 46 35 44 39 31 32 39 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {36 35 32 30 41 37 39 46 35 41 38 33 32 46 39 44 34 32 33 38 43 32 43 32 38 34 31 44 38 39 41 33 32 34 36 46 37 45 46 32 42 30 31 38 35 43 37 33 35 32 36 37 44 37 44 34 31 46 35 44 39 31 32 39 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\6520A79F5A832F9D4238C2C2841D89A3246F7EF2B0185C735267D7D41F5D9129.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_EP_2147905835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.EP"
        threat_id = "2147905835"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:8D545FF434C6B990054C6181BFB409CBE394A697EB703877499F97AD4462A811" wide //weight: 1
        $x_1_2 = {38 44 35 34 35 46 46 34 33 34 43 36 42 39 39 30 30 35 34 43 36 31 38 31 42 46 42 34 30 39 43 42 45 33 39 34 41 36 39 37 45 42 37 30 33 38 37 37 34 39 39 46 39 37 41 44 34 34 36 32 41 38 31 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {38 44 35 34 35 46 46 34 33 34 43 36 42 39 39 30 30 35 34 43 36 31 38 31 42 46 42 34 30 39 43 42 45 33 39 34 41 36 39 37 45 42 37 30 33 38 37 37 34 39 39 46 39 37 41 44 34 34 36 32 41 38 31 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\8D545FF434C6B990054C6181BFB409CBE394A697EB703877499F97AD4462A811.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_EQ_2147905936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.EQ"
        threat_id = "2147905936"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:7C35408411AEEBD53CDBCEBAB167D7B22F1E66614E89DFCB62EE835416F60E1B" wide //weight: 1
        $x_1_2 = {37 43 33 35 34 30 38 34 31 31 41 45 45 42 44 35 33 43 44 42 43 45 42 41 42 31 36 37 44 37 42 32 32 46 31 45 36 36 36 31 34 45 38 39 44 46 43 42 36 32 45 45 38 33 35 34 31 36 46 36 30 45 31 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {37 43 33 35 34 30 38 34 31 31 41 45 45 42 44 35 33 43 44 42 43 45 42 41 42 31 36 37 44 37 42 32 32 46 31 45 36 36 36 31 34 45 38 39 44 46 43 42 36 32 45 45 38 33 35 34 31 36 46 36 30 45 31 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\7C35408411AEEBD53CDBCEBAB167D7B22F1E66614E89DFCB62EE835416F60E1B.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_ER_2147906023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.ER"
        threat_id = "2147906023"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:A8AD0FD4C931CDAA1408D5A60CBF38CEDF46B41E19A8A55E4EF1F1848AF3416A" wide //weight: 1
        $x_1_2 = {41 38 41 44 30 46 44 34 43 39 33 31 43 44 41 41 31 34 30 38 44 35 41 36 30 43 42 46 33 38 43 45 44 46 34 36 42 34 31 45 31 39 41 38 41 35 35 45 34 45 46 31 46 31 38 34 38 41 46 33 34 31 36 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {41 38 41 44 30 46 44 34 43 39 33 31 43 44 41 41 31 34 30 38 44 35 41 36 30 43 42 46 33 38 43 45 44 46 34 36 42 34 31 45 31 39 41 38 41 35 35 45 34 45 46 31 46 31 38 34 38 41 46 33 34 31 36 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\A8AD0FD4C931CDAA1408D5A60CBF38CEDF46B41E19A8A55E4EF1F1848AF3416A.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_ES_2147906139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.ES"
        threat_id = "2147906139"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:2793D009872AF80ED9B1A461F7B9BD6209744047DC1707A42CB622053716AD4B" wide //weight: 1
        $x_1_2 = {32 37 39 33 44 30 30 39 38 37 32 41 46 38 30 45 44 39 42 31 41 34 36 31 46 37 42 39 42 44 36 32 30 39 37 34 34 30 34 37 44 43 31 37 30 37 41 34 32 43 42 36 32 32 30 35 33 37 31 36 41 44 34 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {32 37 39 33 44 30 30 39 38 37 32 41 46 38 30 45 44 39 42 31 41 34 36 31 46 37 42 39 42 44 36 32 30 39 37 34 34 30 34 37 44 43 31 37 30 37 41 34 32 43 42 36 32 32 30 35 33 37 31 36 41 44 34 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\2793D009872AF80ED9B1A461F7B9BD6209744047DC1707A42CB622053716AD4B.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_ET_2147906143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.ET"
        threat_id = "2147906143"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:AEA72DFCF492037A6D15755A74645C7D8E674E342BACA9F9070A3FB74117EC31" wide //weight: 1
        $x_1_2 = {41 45 41 37 32 44 46 43 46 34 39 32 30 33 37 41 36 44 31 35 37 35 35 41 37 34 36 34 35 43 37 44 38 45 36 37 34 45 33 34 32 42 41 43 41 39 46 39 30 37 30 41 33 46 42 37 34 31 31 37 45 43 33 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {41 45 41 37 32 44 46 43 46 34 39 32 30 33 37 41 36 44 31 35 37 35 35 41 37 34 36 34 35 43 37 44 38 45 36 37 34 45 33 34 32 42 41 43 41 39 46 39 30 37 30 41 33 46 42 37 34 31 31 37 45 43 33 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\AEA72DFCF492037A6D15755A74645C7D8E674E342BACA9F9070A3FB74117EC31.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_EU_2147906147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.EU"
        threat_id = "2147906147"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:BD0FC8C016657DE254C0F48AA3472E11B8C92F96DAF66F971ABF5B8AE7409E2F" wide //weight: 1
        $x_1_2 = {42 44 30 46 43 38 43 30 31 36 36 35 37 44 45 32 35 34 43 30 46 34 38 41 41 33 34 37 32 45 31 31 42 38 43 39 32 46 39 36 44 41 46 36 36 46 39 37 31 41 42 46 35 42 38 41 45 37 34 30 39 45 32 46 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {42 44 30 46 43 38 43 30 31 36 36 35 37 44 45 32 35 34 43 30 46 34 38 41 41 33 34 37 32 45 31 31 42 38 43 39 32 46 39 36 44 41 46 36 36 46 39 37 31 41 42 46 35 42 38 41 45 37 34 30 39 45 32 46 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\BD0FC8C016657DE254C0F48AA3472E11B8C92F96DAF66F971ABF5B8AE7409E2F.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_EW_2147907281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.EW"
        threat_id = "2147907281"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:4CDE9AA5707C619C241A2F27E0F3378E6A5CC6AD031EADC40C36F1F300DB8D5B" wide //weight: 1
        $x_1_2 = {34 43 44 45 39 41 41 35 37 30 37 43 36 31 39 43 32 34 31 41 32 46 32 37 45 30 46 33 33 37 38 45 36 41 35 43 43 36 41 44 30 33 31 45 41 44 43 34 30 43 33 36 46 31 46 33 30 30 44 42 38 44 35 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {34 43 44 45 39 41 41 35 37 30 37 43 36 31 39 43 32 34 31 41 32 46 32 37 45 30 46 33 33 37 38 45 36 41 35 43 43 36 41 44 30 33 31 45 41 44 43 34 30 43 33 36 46 31 46 33 30 30 44 42 38 44 35 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\4CDE9AA5707C619C241A2F27E0F3378E6A5CC6AD031EADC40C36F1F300DB8D5B.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_EX_2147907285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.EX"
        threat_id = "2147907285"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:9A8B9576F0B3846B4CA8B4FAF9F50F633CE731BBC860E76C09ED31FC1A1ACF2A" wide //weight: 1
        $x_1_2 = {39 41 38 42 39 35 37 36 46 30 42 33 38 34 36 42 34 43 41 38 42 34 46 41 46 39 46 35 30 46 36 33 33 43 45 37 33 31 42 42 43 38 36 30 45 37 36 43 30 39 45 44 33 31 46 43 31 41 31 41 43 46 32 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {39 41 38 42 39 35 37 36 46 30 42 33 38 34 36 42 34 43 41 38 42 34 46 41 46 39 46 35 30 46 36 33 33 43 45 37 33 31 42 42 43 38 36 30 45 37 36 43 30 39 45 44 33 31 46 43 31 41 31 41 43 46 32 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\9A8B9576F0B3846B4CA8B4FAF9F50F633CE731BBC860E76C09ED31FC1A1ACF2A.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_EY_2147907289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.EY"
        threat_id = "2147907289"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:358AC0F6C813DD4FD243524F040E2F77969278274BD8A8945B5041A249786E32" wide //weight: 1
        $x_1_2 = {33 35 38 41 43 30 46 36 43 38 31 33 44 44 34 46 44 32 34 33 35 32 34 46 30 34 30 45 32 46 37 37 39 36 39 32 37 38 32 37 34 42 44 38 41 38 39 34 35 42 35 30 34 31 41 32 34 39 37 38 36 45 33 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {33 35 38 41 43 30 46 36 43 38 31 33 44 44 34 46 44 32 34 33 35 32 34 46 30 34 30 45 32 46 37 37 39 36 39 32 37 38 32 37 34 42 44 38 41 38 39 34 35 42 35 30 34 31 41 32 34 39 37 38 36 45 33 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\358AC0F6C813DD4FD243524F040E2F77969278274BD8A8945B5041A249786E32.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_EZ_2147907333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.EZ"
        threat_id = "2147907333"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:285CFEC2BC80A8A698B3E4E0C86A0FCB329569DAA16EA11FD028774E26BDD97D" wide //weight: 1
        $x_1_2 = {32 38 35 43 46 45 43 32 42 43 38 30 41 38 41 36 39 38 42 33 45 34 45 30 43 38 36 41 30 46 43 42 33 32 39 35 36 39 44 41 41 31 36 45 41 31 31 46 44 30 32 38 37 37 34 45 32 36 42 44 44 39 37 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {32 38 35 43 46 45 43 32 42 43 38 30 41 38 41 36 39 38 42 33 45 34 45 30 43 38 36 41 30 46 43 42 33 32 39 35 36 39 44 41 41 31 36 45 41 31 31 46 44 30 32 38 37 37 34 45 32 36 42 44 44 39 37 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\285CFEC2BC80A8A698B3E4E0C86A0FCB329569DAA16EA11FD028774E26BDD97D.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_FA_2147907401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.FA"
        threat_id = "2147907401"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:DCBB9DDEA640A6A68FD8205B7C160D6F91FF9C3B0AE73ABDB6D426543BCAFA7A" wide //weight: 1
        $x_1_2 = {44 43 42 42 39 44 44 45 41 36 34 30 41 36 41 36 38 46 44 38 32 30 35 42 37 43 31 36 30 44 36 46 39 31 46 46 39 43 33 42 30 41 45 37 33 41 42 44 42 36 44 34 32 36 35 34 33 42 43 41 46 41 37 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {44 43 42 42 39 44 44 45 41 36 34 30 41 36 41 36 38 46 44 38 32 30 35 42 37 43 31 36 30 44 36 46 39 31 46 46 39 43 33 42 30 41 45 37 33 41 42 44 42 36 44 34 32 36 35 34 33 42 43 41 46 41 37 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\DCBB9DDEA640A6A68FD8205B7C160D6F91FF9C3B0AE73ABDB6D426543BCAFA7A.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_FB_2147907405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.FB"
        threat_id = "2147907405"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:BE34052204E43C950AF5114D0B52F359C8FED65BFBD7B80097B96FD554362334" wide //weight: 1
        $x_1_2 = {42 45 33 34 30 35 32 32 30 34 45 34 33 43 39 35 30 41 46 35 31 31 34 44 30 42 35 32 46 33 35 39 43 38 46 45 44 36 35 42 46 42 44 37 42 38 30 30 39 37 42 39 36 46 44 35 35 34 33 36 32 33 33 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {42 45 33 34 30 35 32 32 30 34 45 34 33 43 39 35 30 41 46 35 31 31 34 44 30 42 35 32 46 33 35 39 43 38 46 45 44 36 35 42 46 42 44 37 42 38 30 30 39 37 42 39 36 46 44 35 35 34 33 36 32 33 33 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\BE34052204E43C950AF5114D0B52F359C8FED65BFBD7B80097B96FD554362334.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_FC_2147907409_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.FC"
        threat_id = "2147907409"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:14607D9D78CDD2CE718B6C7F4C4087A6F8EE37E37EA93830B6D02AA0DDB88266" wide //weight: 1
        $x_1_2 = {31 34 36 30 37 44 39 44 37 38 43 44 44 32 43 45 37 31 38 42 36 43 37 46 34 43 34 30 38 37 41 36 46 38 45 45 33 37 45 33 37 45 41 39 33 38 33 30 42 36 44 30 32 41 41 30 44 44 42 38 38 32 36 36 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {31 34 36 30 37 44 39 44 37 38 43 44 44 32 43 45 37 31 38 42 36 43 37 46 34 43 34 30 38 37 41 36 46 38 45 45 33 37 45 33 37 45 41 39 33 38 33 30 42 36 44 30 32 41 41 30 44 44 42 38 38 32 36 36 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\14607D9D78CDD2CE718B6C7F4C4087A6F8EE37E37EA93830B6D02AA0DDB88266.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_FD_2147907748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.FD"
        threat_id = "2147907748"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:ED27769A3F1FCD0A16D9D40776770ACFD694BDEDBD7D926F28A77C185792B852" wide //weight: 1
        $x_1_2 = {45 44 32 37 37 36 39 41 33 46 31 46 43 44 30 41 31 36 44 39 44 34 30 37 37 36 37 37 30 41 43 46 44 36 39 34 42 44 45 44 42 44 37 44 39 32 36 46 32 38 41 37 37 43 31 38 35 37 39 32 42 38 35 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {45 44 32 37 37 36 39 41 33 46 31 46 43 44 30 41 31 36 44 39 44 34 30 37 37 36 37 37 30 41 43 46 44 36 39 34 42 44 45 44 42 44 37 44 39 32 36 46 32 38 41 37 37 43 31 38 35 37 39 32 42 38 35 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\ED27769A3F1FCD0A16D9D40776770ACFD694BDEDBD7D926F28A77C185792B852.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_FE_2147908362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.FE"
        threat_id = "2147908362"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:B346F0ECF601FC1E2EF530602790B1EDA7A61E1AE23110C68F513F9F9646C910" wide //weight: 1
        $x_1_2 = {42 33 34 36 46 30 45 43 46 36 30 31 46 43 31 45 32 45 46 35 33 30 36 30 32 37 39 30 42 31 45 44 41 37 41 36 31 45 31 41 45 32 33 31 31 30 43 36 38 46 35 31 33 46 39 46 39 36 34 36 43 39 31 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {42 33 34 36 46 30 45 43 46 36 30 31 46 43 31 45 32 45 46 35 33 30 36 30 32 37 39 30 42 31 45 44 41 37 41 36 31 45 31 41 45 32 33 31 31 30 43 36 38 46 35 31 33 46 39 46 39 36 34 36 43 39 31 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\B346F0ECF601FC1E2EF530602790B1EDA7A61E1AE23110C68F513F9F9646C910.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_FF_2147909573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.FF"
        threat_id = "2147909573"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:1097C77415E419164E4E5229CF57B19586C2F30C1050306BF4127CDC6391D44D" wide //weight: 1
        $x_1_2 = {31 30 39 37 43 37 37 34 31 35 45 34 31 39 31 36 34 45 34 45 35 32 32 39 43 46 35 37 42 31 39 35 38 36 43 32 46 33 30 43 31 30 35 30 33 30 36 42 46 34 31 32 37 43 44 43 36 33 39 31 44 34 34 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {31 30 39 37 43 37 37 34 31 35 45 34 31 39 31 36 34 45 34 45 35 32 32 39 43 46 35 37 42 31 39 35 38 36 43 32 46 33 30 43 31 30 35 30 33 30 36 42 46 34 31 32 37 43 44 43 36 33 39 31 44 34 34 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\1097C77415E419164E4E5229CF57B19586C2F30C1050306BF4127CDC6391D44D.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_FG_2147909577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.FG"
        threat_id = "2147909577"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:1D1C4B6CC456727CFD622AC25E4E81FF3826AECD75A4E8A21E4D293EBBB2A14D" wide //weight: 1
        $x_1_2 = {31 44 31 43 34 42 36 43 43 34 35 36 37 32 37 43 46 44 36 32 32 41 43 32 35 45 34 45 38 31 46 46 33 38 32 36 41 45 43 44 37 35 41 34 45 38 41 32 31 45 34 44 32 39 33 45 42 42 42 32 41 31 34 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {31 44 31 43 34 42 36 43 43 34 35 36 37 32 37 43 46 44 36 32 32 41 43 32 35 45 34 45 38 31 46 46 33 38 32 36 41 45 43 44 37 35 41 34 45 38 41 32 31 45 34 44 32 39 33 45 42 42 42 32 41 31 34 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\1D1C4B6CC456727CFD622AC25E4E81FF3826AECD75A4E8A21E4D293EBBB2A14D.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_FH_2147909581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.FH"
        threat_id = "2147909581"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:9796CE1E72A8874D594F6573F44C94FB649473B4194DCD80C406BFE88E4B3662" wide //weight: 1
        $x_1_2 = {39 37 39 36 43 45 31 45 37 32 41 38 38 37 34 44 35 39 34 46 36 35 37 33 46 34 34 43 39 34 46 42 36 34 39 34 37 33 42 34 31 39 34 44 43 44 38 30 43 34 30 36 42 46 45 38 38 45 34 42 33 36 36 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {39 37 39 36 43 45 31 45 37 32 41 38 38 37 34 44 35 39 34 46 36 35 37 33 46 34 34 43 39 34 46 42 36 34 39 34 37 33 42 34 31 39 34 44 43 44 38 30 43 34 30 36 42 46 45 38 38 45 34 42 33 36 36 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\9796CE1E72A8874D594F6573F44C94FB649473B4194DCD80C406BFE88E4B3662.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_FI_2147909585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.FI"
        threat_id = "2147909585"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:A7D21906457B8877A15F4AD0F236242FE431966C3D17B14A8E8CD15B4B60B56E" wide //weight: 1
        $x_1_2 = {41 37 44 32 31 39 30 36 34 35 37 42 38 38 37 37 41 31 35 46 34 41 44 30 46 32 33 36 32 34 32 46 45 34 33 31 39 36 36 43 33 44 31 37 42 31 34 41 38 45 38 43 44 31 35 42 34 42 36 30 42 35 36 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {41 37 44 32 31 39 30 36 34 35 37 42 38 38 37 37 41 31 35 46 34 41 44 30 46 32 33 36 32 34 32 46 45 34 33 31 39 36 36 43 33 44 31 37 42 31 34 41 38 45 38 43 44 31 35 42 34 42 36 30 42 35 36 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\A7D21906457B8877A15F4AD0F236242FE431966C3D17B14A8E8CD15B4B60B56E.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_FJ_2147910394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.FJ"
        threat_id = "2147910394"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:91A120F1D2E4A2DAEA82E3043D98AFE58DAAFC1A639ADFB624C45D9BDA148D22" wide //weight: 1
        $x_1_2 = {39 31 41 31 32 30 46 31 44 32 45 34 41 32 44 41 45 41 38 32 45 33 30 34 33 44 39 38 41 46 45 35 38 44 41 41 46 43 31 41 36 33 39 41 44 46 42 36 32 34 43 34 35 44 39 42 44 41 31 34 38 44 32 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {39 31 41 31 32 30 46 31 44 32 45 34 41 32 44 41 45 41 38 32 45 33 30 34 33 44 39 38 41 46 45 35 38 44 41 41 46 43 31 41 36 33 39 41 44 46 42 36 32 34 43 34 35 44 39 42 44 41 31 34 38 44 32 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\91A120F1D2E4A2DAEA82E3043D98AFE58DAAFC1A639ADFB624C45D9BDA148D22.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_FK_2147910396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.FK"
        threat_id = "2147910396"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:3C588D36EF676201701B0B8EA1F8046E0B2372EBCF900008E80B0DE02F39DD25" wide //weight: 1
        $x_1_2 = {33 43 35 38 38 44 33 36 45 46 36 37 36 32 30 31 37 30 31 42 30 42 38 45 41 31 46 38 30 34 36 45 30 42 32 33 37 32 45 42 43 46 39 30 30 30 30 38 45 38 30 42 30 44 45 30 32 46 33 39 44 44 32 35 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {33 43 35 38 38 44 33 36 45 46 36 37 36 32 30 31 37 30 31 42 30 42 38 45 41 31 46 38 30 34 36 45 30 42 32 33 37 32 45 42 43 46 39 30 30 30 30 38 45 38 30 42 30 44 45 30 32 46 33 39 44 44 32 35 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\3C588D36EF676201701B0B8EA1F8046E0B2372EBCF900008E80B0DE02F39DD25.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_FL_2147910714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.FL"
        threat_id = "2147910714"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:A466C1720D92FF9A57241E24BA38E2AF9896FCD250FCC85E7E43E05871FB655C" wide //weight: 1
        $x_1_2 = {41 34 36 36 43 31 37 32 30 44 39 32 46 46 39 41 35 37 32 34 31 45 32 34 42 41 33 38 45 32 41 46 39 38 39 36 46 43 44 32 35 30 46 43 43 38 35 45 37 45 34 33 45 30 35 38 37 31 46 42 36 35 35 43 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {41 34 36 36 43 31 37 32 30 44 39 32 46 46 39 41 35 37 32 34 31 45 32 34 42 41 33 38 45 32 41 46 39 38 39 36 46 43 44 32 35 30 46 43 43 38 35 45 37 45 34 33 45 30 35 38 37 31 46 42 36 35 35 43 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\A466C1720D92FF9A57241E24BA38E2AF9896FCD250FCC85E7E43E05871FB655C.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_FM_2147910718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.FM"
        threat_id = "2147910718"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:88A612B3887D57A7FA3D48F5E3EDF952E4BE48E0972FC6456FBBCFF198CC8620" wide //weight: 1
        $x_1_2 = {38 38 41 36 31 32 42 33 38 38 37 44 35 37 41 37 46 41 33 44 34 38 46 35 45 33 45 44 46 39 35 32 45 34 42 45 34 38 45 30 39 37 32 46 43 36 34 35 36 46 42 42 43 46 46 31 39 38 43 43 38 36 32 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {38 38 41 36 31 32 42 33 38 38 37 44 35 37 41 37 46 41 33 44 34 38 46 35 45 33 45 44 46 39 35 32 45 34 42 45 34 38 45 30 39 37 32 46 43 36 34 35 36 46 42 42 43 46 46 31 39 38 43 43 38 36 32 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\88A612B3887D57A7FA3D48F5E3EDF952E4BE48E0972FC6456FBBCFF198CC8620.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_FN_2147910865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.FN"
        threat_id = "2147910865"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:36F186C6FDCAAC0CF122E234B5D15F3F42F73568745F251C1306D71EBCA96817" wide //weight: 1
        $x_1_2 = {33 36 46 31 38 36 43 36 46 44 43 41 41 43 30 43 46 31 32 32 45 32 33 34 42 35 44 31 35 46 33 46 34 32 46 37 33 35 36 38 37 34 35 46 32 35 31 43 31 33 30 36 44 37 31 45 42 43 41 39 36 38 31 37 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {33 36 46 31 38 36 43 36 46 44 43 41 41 43 30 43 46 31 32 32 45 32 33 34 42 35 44 31 35 46 33 46 34 32 46 37 33 35 36 38 37 34 35 46 32 35 31 43 31 33 30 36 44 37 31 45 42 43 41 39 36 38 31 37 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\36F186C6FDCAAC0CF122E234B5D15F3F42F73568745F251C1306D71EBCA96817.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_FO_2147911106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.FO"
        threat_id = "2147911106"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:6C532A1EEBC9225639D91BDECFE9F7B0ADC0582083C5C0BE188F43CC0F482A40" wide //weight: 1
        $x_1_2 = {36 43 35 33 32 41 31 45 45 42 43 39 32 32 35 36 33 39 44 39 31 42 44 45 43 46 45 39 46 37 42 30 41 44 43 30 35 38 32 30 38 33 43 35 43 30 42 45 31 38 38 46 34 33 43 43 30 46 34 38 32 41 34 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {36 43 35 33 32 41 31 45 45 42 43 39 32 32 35 36 33 39 44 39 31 42 44 45 43 46 45 39 46 37 42 30 41 44 43 30 35 38 32 30 38 33 43 35 43 30 42 45 31 38 38 46 34 33 43 43 30 46 34 38 32 41 34 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\6C532A1EEBC9225639D91BDECFE9F7B0ADC0582083C5C0BE188F43CC0F482A40.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_FP_2147911431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.FP"
        threat_id = "2147911431"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:A7A86A6C92CC034E621B58C4DDDD3542957C8019A141C6F4D138D8451882654A" wide //weight: 1
        $x_1_2 = {41 37 41 38 36 41 36 43 39 32 43 43 30 33 34 45 36 32 31 42 35 38 43 34 44 44 44 44 33 35 34 32 39 35 37 43 38 30 31 39 41 31 34 31 43 36 46 34 44 31 33 38 44 38 34 35 31 38 38 32 36 35 34 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {41 37 41 38 36 41 36 43 39 32 43 43 30 33 34 45 36 32 31 42 35 38 43 34 44 44 44 44 33 35 34 32 39 35 37 43 38 30 31 39 41 31 34 31 43 36 46 34 44 31 33 38 44 38 34 35 31 38 38 32 36 35 34 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\A7A86A6C92CC034E621B58C4DDDD3542957C8019A141C6F4D138D8451882654A.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_FQ_2147911561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.FQ"
        threat_id = "2147911561"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:2D164BEB09DF775C543F52C7AD8755B96FBB3A19C8AEAB0C93EFCE3C74E4A703" wide //weight: 1
        $x_1_2 = {32 44 31 36 34 42 45 42 30 39 44 46 37 37 35 43 35 34 33 46 35 32 43 37 41 44 38 37 35 35 42 39 36 46 42 42 33 41 31 39 43 38 41 45 41 42 30 43 39 33 45 46 43 45 33 43 37 34 45 34 41 37 30 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {32 44 31 36 34 42 45 42 30 39 44 46 37 37 35 43 35 34 33 46 35 32 43 37 41 44 38 37 35 35 42 39 36 46 42 42 33 41 31 39 43 38 41 45 41 42 30 43 39 33 45 46 43 45 33 43 37 34 45 34 41 37 30 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\2D164BEB09DF775C543F52C7AD8755B96FBB3A19C8AEAB0C93EFCE3C74E4A703.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_FR_2147911565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.FR"
        threat_id = "2147911565"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:A504DF3588EC05145E2C42EF8F214F3246D5E3526B05ECCC21EDC6783992C43E" wide //weight: 1
        $x_1_2 = {41 35 30 34 44 46 33 35 38 38 45 43 30 35 31 34 35 45 32 43 34 32 45 46 38 46 32 31 34 46 33 32 34 36 44 35 45 33 35 32 36 42 30 35 45 43 43 43 32 31 45 44 43 36 37 38 33 39 39 32 43 34 33 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {41 35 30 34 44 46 33 35 38 38 45 43 30 35 31 34 35 45 32 43 34 32 45 46 38 46 32 31 34 46 33 32 34 36 44 35 45 33 35 32 36 42 30 35 45 43 43 43 32 31 45 44 43 36 37 38 33 39 39 32 43 34 33 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\A504DF3588EC05145E2C42EF8F214F3246D5E3526B05ECCC21EDC6783992C43E.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_FS_2147911569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.FS"
        threat_id = "2147911569"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:14CEE2E9F5B0F5D10378ED08C7C52552EF425D12CB03EE7462E938AE82735F2B" wide //weight: 1
        $x_1_2 = {31 34 43 45 45 32 45 39 46 35 42 30 46 35 44 31 30 33 37 38 45 44 30 38 43 37 43 35 32 35 35 32 45 46 34 32 35 44 31 32 43 42 30 33 45 45 37 34 36 32 45 39 33 38 41 45 38 32 37 33 35 46 32 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {31 34 43 45 45 32 45 39 46 35 42 30 46 35 44 31 30 33 37 38 45 44 30 38 43 37 43 35 32 35 35 32 45 46 34 32 35 44 31 32 43 42 30 33 45 45 37 34 36 32 45 39 33 38 41 45 38 32 37 33 35 46 32 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\14CEE2E9F5B0F5D10378ED08C7C52552EF425D12CB03EE7462E938AE82735F2B.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_FT_2147911573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.FT"
        threat_id = "2147911573"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:F01DE6CE6E065F6D4D1022311EBD62238ECC0B06127EB7DD72B8CEE084CFBA42" wide //weight: 1
        $x_1_2 = {46 30 31 44 45 36 43 45 36 45 30 36 35 46 36 44 34 44 31 30 32 32 33 31 31 45 42 44 36 32 32 33 38 45 43 43 30 42 30 36 31 32 37 45 42 37 44 44 37 32 42 38 43 45 45 30 38 34 43 46 42 41 34 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {46 30 31 44 45 36 43 45 36 45 30 36 35 46 36 44 34 44 31 30 32 32 33 31 31 45 42 44 36 32 32 33 38 45 43 43 30 42 30 36 31 32 37 45 42 37 44 44 37 32 42 38 43 45 45 30 38 34 43 46 42 41 34 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\F01DE6CE6E065F6D4D1022311EBD62238ECC0B06127EB7DD72B8CEE084CFBA42.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_FU_2147911701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.FU"
        threat_id = "2147911701"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:F6B2E01CFA4D3F2DB75E4EDD07EC28BF793E541A9674C3E6A66E1CDA9D931A13" wide //weight: 1
        $x_1_2 = {46 36 42 32 45 30 31 43 46 41 34 44 33 46 32 44 42 37 35 45 34 45 44 44 30 37 45 43 32 38 42 46 37 39 33 45 35 34 31 41 39 36 37 34 43 33 45 36 41 36 36 45 31 43 44 41 39 44 39 33 31 41 31 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {46 36 42 32 45 30 31 43 46 41 34 44 33 46 32 44 42 37 35 45 34 45 44 44 30 37 45 43 32 38 42 46 37 39 33 45 35 34 31 41 39 36 37 34 43 33 45 36 41 36 36 45 31 43 44 41 39 44 39 33 31 41 31 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\F6B2E01CFA4D3F2DB75E4EDD07EC28BF793E541A9674C3E6A66E1CDA9D931A13.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_FV_2147913880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.FV"
        threat_id = "2147913880"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:DDD155B43289399E7770F6B8F6AD5D6F5197FAD60F2F823797116AC36A0DEA02" wide //weight: 1
        $x_1_2 = {44 44 44 31 35 35 42 34 33 32 38 39 33 39 39 45 37 37 37 30 46 36 42 38 46 36 41 44 35 44 36 46 35 31 39 37 46 41 44 36 30 46 32 46 38 32 33 37 39 37 31 31 36 41 43 33 36 41 30 44 45 41 30 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {44 44 44 31 35 35 42 34 33 32 38 39 33 39 39 45 37 37 37 30 46 36 42 38 46 36 41 44 35 44 36 46 35 31 39 37 46 41 44 36 30 46 32 46 38 32 33 37 39 37 31 31 36 41 43 33 36 41 30 44 45 41 30 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\DDD155B43289399E7770F6B8F6AD5D6F5197FAD60F2F823797116AC36A0DEA02.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_FW_2147913884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.FW"
        threat_id = "2147913884"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:10FCD323158B14E6BD41CB00CB98AD8E8FE0C9D9B78150F008350BCAC84C1B5D" wide //weight: 1
        $x_1_2 = {31 30 46 43 44 33 32 33 31 35 38 42 31 34 45 36 42 44 34 31 43 42 30 30 43 42 39 38 41 44 38 45 38 46 45 30 43 39 44 39 42 37 38 31 35 30 46 30 30 38 33 35 30 42 43 41 43 38 34 43 31 42 35 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {31 30 46 43 44 33 32 33 31 35 38 42 31 34 45 36 42 44 34 31 43 42 30 30 43 42 39 38 41 44 38 45 38 46 45 30 43 39 44 39 42 37 38 31 35 30 46 30 30 38 33 35 30 42 43 41 43 38 34 43 31 42 35 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\10FCD323158B14E6BD41CB00CB98AD8E8FE0C9D9B78150F008350BCAC84C1B5D.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_FX_2147913888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.FX"
        threat_id = "2147913888"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:1E62672989582C08F5C5F1B0185ACF4281A571CE4115C0EB019B972187B18855" wide //weight: 1
        $x_1_2 = {31 45 36 32 36 37 32 39 38 39 35 38 32 43 30 38 46 35 43 35 46 31 42 30 31 38 35 41 43 46 34 32 38 31 41 35 37 31 43 45 34 31 31 35 43 30 45 42 30 31 39 42 39 37 32 31 38 37 42 31 38 38 35 35 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {31 45 36 32 36 37 32 39 38 39 35 38 32 43 30 38 46 35 43 35 46 31 42 30 31 38 35 41 43 46 34 32 38 31 41 35 37 31 43 45 34 31 31 35 43 30 45 42 30 31 39 42 39 37 32 31 38 37 42 31 38 38 35 35 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\1E62672989582C08F5C5F1B0185ACF4281A571CE4115C0EB019B972187B18855.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_FY_2147915540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.FY"
        threat_id = "2147915540"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:9500B1A73716BCF40745086F7184A33EA0141B7D3F852431C8FDD2E1E8FAF927" wide //weight: 1
        $x_1_2 = {39 35 30 30 42 31 41 37 33 37 31 36 42 43 46 34 30 37 34 35 30 38 36 46 37 31 38 34 41 33 33 45 41 30 31 34 31 42 37 44 33 46 38 35 32 34 33 31 43 38 46 44 44 32 45 31 45 38 46 41 46 39 32 37 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {39 35 30 30 42 31 41 37 33 37 31 36 42 43 46 34 30 37 34 35 30 38 36 46 37 31 38 34 41 33 33 45 41 30 31 34 31 42 37 44 33 46 38 35 32 34 33 31 43 38 46 44 44 32 45 31 45 38 46 41 46 39 32 37 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\9500B1A73716BCF40745086F7184A33EA0141B7D3F852431C8FDD2E1E8FAF927.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_FZ_2147916039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.FZ"
        threat_id = "2147916039"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:6055FA73B7D94FE77A34502A664D95A439F18A72C0042915A7EEBE09F4ACF023" wide //weight: 1
        $x_1_2 = {36 30 35 35 46 41 37 33 42 37 44 39 34 46 45 37 37 41 33 34 35 30 32 41 36 36 34 44 39 35 41 34 33 39 46 31 38 41 37 32 43 30 30 34 32 39 31 35 41 37 45 45 42 45 30 39 46 34 41 43 46 30 32 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {36 30 35 35 46 41 37 33 42 37 44 39 34 46 45 37 37 41 33 34 35 30 32 41 36 36 34 44 39 35 41 34 33 39 46 31 38 41 37 32 43 30 30 34 32 39 31 35 41 37 45 45 42 45 30 39 46 34 41 43 46 30 32 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\6055FA73B7D94FE77A34502A664D95A439F18A72C0042915A7EEBE09F4ACF023.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_GA_2147917461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.GA"
        threat_id = "2147917461"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:D4CDADA0C4345AFDE8A1FD2731D9B367D635330273E25FB1DBFD468608F15404" wide //weight: 1
        $x_1_2 = {44 34 43 44 41 44 41 30 43 34 33 34 35 41 46 44 45 38 41 31 46 44 32 37 33 31 44 39 42 33 36 37 44 36 33 35 33 33 30 32 37 33 45 32 35 46 42 31 44 42 46 44 34 36 38 36 30 38 46 31 35 34 30 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {44 34 43 44 41 44 41 30 43 34 33 34 35 41 46 44 45 38 41 31 46 44 32 37 33 31 44 39 42 33 36 37 44 36 33 35 33 33 30 32 37 33 45 32 35 46 42 31 44 42 46 44 34 36 38 36 30 38 46 31 35 34 30 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\D4CDADA0C4345AFDE8A1FD2731D9B367D635330273E25FB1DBFD468608F15404.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_GB_2147917465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.GB"
        threat_id = "2147917465"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:141C8F13F4B7A4C2EED05A29186AE10F8E849AE4AC2C3E7B167FD27B316E026A" wide //weight: 1
        $x_1_2 = {31 34 31 43 38 46 31 33 46 34 42 37 41 34 43 32 45 45 44 30 35 41 32 39 31 38 36 41 45 31 30 46 38 45 38 34 39 41 45 34 41 43 32 43 33 45 37 42 31 36 37 46 44 32 37 42 33 31 36 45 30 32 36 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {31 34 31 43 38 46 31 33 46 34 42 37 41 34 43 32 45 45 44 30 35 41 32 39 31 38 36 41 45 31 30 46 38 45 38 34 39 41 45 34 41 43 32 43 33 45 37 42 31 36 37 46 44 32 37 42 33 31 36 45 30 32 36 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\141C8F13F4B7A4C2EED05A29186AE10F8E849AE4AC2C3E7B167FD27B316E026A.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_GC_2147919466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.GC"
        threat_id = "2147919466"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:983E2254D2BDC97E9EE54216C50F12706D3AF0FD6FD19596B676925ECA38FA2C" wide //weight: 1
        $x_1_2 = {39 38 33 45 32 32 35 34 44 32 42 44 43 39 37 45 39 45 45 35 34 32 31 36 43 35 30 46 31 32 37 30 36 44 33 41 46 30 46 44 36 46 44 31 39 35 39 36 42 36 37 36 39 32 35 45 43 41 33 38 46 41 32 43 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {39 38 33 45 32 32 35 34 44 32 42 44 43 39 37 45 39 45 45 35 34 32 31 36 43 35 30 46 31 32 37 30 36 44 33 41 46 30 46 44 36 46 44 31 39 35 39 36 42 36 37 36 39 32 35 45 43 41 33 38 46 41 32 43 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\983E2254D2BDC97E9EE54216C50F12706D3AF0FD6FD19596B676925ECA38FA2C.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_GD_2147919691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.GD"
        threat_id = "2147919691"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:960D9814EFBFC89823219ECCD31B173B1CB9975E181FFD2AF539E09A2CDE7E65" wide //weight: 1
        $x_1_2 = {39 36 30 44 39 38 31 34 45 46 42 46 43 38 39 38 32 33 32 31 39 45 43 43 44 33 31 42 31 37 33 42 31 43 42 39 39 37 35 45 31 38 31 46 46 44 32 41 46 35 33 39 45 30 39 41 32 43 44 45 37 45 36 35 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {39 36 30 44 39 38 31 34 45 46 42 46 43 38 39 38 32 33 32 31 39 45 43 43 44 33 31 42 31 37 33 42 31 43 42 39 39 37 35 45 31 38 31 46 46 44 32 41 46 35 33 39 45 30 39 41 32 43 44 45 37 45 36 35 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\960D9814EFBFC89823219ECCD31B173B1CB9975E181FFD2AF539E09A2CDE7E65.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_GE_2147920299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.GE"
        threat_id = "2147920299"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:5700F2F2B10F590AAEEE1C6FA0410CA40A6CD08852B7A1FA26A37A6A06E1A40C" wide //weight: 1
        $x_1_2 = {35 37 30 30 46 32 46 32 42 31 30 46 35 39 30 41 41 45 45 45 31 43 36 46 41 30 34 31 30 43 41 34 30 41 36 43 44 30 38 38 35 32 42 37 41 31 46 41 32 36 41 33 37 41 36 41 30 36 45 31 41 34 30 43 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {35 37 30 30 46 32 46 32 42 31 30 46 35 39 30 41 41 45 45 45 31 43 36 46 41 30 34 31 30 43 41 34 30 41 36 43 44 30 38 38 35 32 42 37 41 31 46 41 32 36 41 33 37 41 36 41 30 36 45 31 41 34 30 43 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\5700F2F2B10F590AAEEE1C6FA0410CA40A6CD08852B7A1FA26A37A6A06E1A40C.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_GF_2147920303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.GF"
        threat_id = "2147920303"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:C2572C8DE4E77D02E8FFC0F9F96FD0F18CCD19C0B6D45E1EA7EFE26203D8DB03" wide //weight: 1
        $x_1_2 = {43 32 35 37 32 43 38 44 45 34 45 37 37 44 30 32 45 38 46 46 43 30 46 39 46 39 36 46 44 30 46 31 38 43 43 44 31 39 43 30 42 36 44 34 35 45 31 45 41 37 45 46 45 32 36 32 30 33 44 38 44 42 30 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {43 32 35 37 32 43 38 44 45 34 45 37 37 44 30 32 45 38 46 46 43 30 46 39 46 39 36 46 44 30 46 31 38 43 43 44 31 39 43 30 42 36 44 34 35 45 31 45 41 37 45 46 45 32 36 32 30 33 44 38 44 42 30 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\C2572C8DE4E77D02E8FFC0F9F96FD0F18CCD19C0B6D45E1EA7EFE26203D8DB03.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_EV_2147920489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.EV"
        threat_id = "2147920489"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:B9B74A412D44C19EEA0343F6146B6C7139221B86390D5597EBE9A2E4FB987A39" wide //weight: 1
        $x_1_2 = {42 39 42 37 34 41 34 31 32 44 34 34 43 31 39 45 45 41 30 33 34 33 46 36 31 34 36 42 36 43 37 31 33 39 32 32 31 42 38 36 33 39 30 44 35 35 39 37 45 42 45 39 41 32 45 34 46 42 39 38 37 41 33 39 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {42 39 42 37 34 41 34 31 32 44 34 34 43 31 39 45 45 41 30 33 34 33 46 36 31 34 36 42 36 43 37 31 33 39 32 32 31 42 38 36 33 39 30 44 35 35 39 37 45 42 45 39 41 32 45 34 46 42 39 38 37 41 33 39 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\B9B74A412D44C19EEA0343F6146B6C7139221B86390D5597EBE9A2E4FB987A39.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_GG_2147921809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.GG"
        threat_id = "2147921809"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:DAF390020DB15B4D2822803CC3F4D69EC81D37552B485037261D688F8901665A" wide //weight: 1
        $x_1_2 = {44 41 46 33 39 30 30 32 30 44 42 31 35 42 34 44 32 38 32 32 38 30 33 43 43 33 46 34 44 36 39 45 43 38 31 44 33 37 35 35 32 42 34 38 35 30 33 37 32 36 31 44 36 38 38 46 38 39 30 31 36 36 35 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {44 41 46 33 39 30 30 32 30 44 42 31 35 42 34 44 32 38 32 32 38 30 33 43 43 33 46 34 44 36 39 45 43 38 31 44 33 37 35 35 32 42 34 38 35 30 33 37 32 36 31 44 36 38 38 46 38 39 30 31 36 36 35 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\DAF390020DB15B4D2822803CC3F4D69EC81D37552B485037261D688F8901665A.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_GH_2147921813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.GH"
        threat_id = "2147921813"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:605399A938178E58CC9CB73F1D9836DAEC173361DBDA1CB98B8C018B2FC23352" wide //weight: 1
        $x_1_2 = {36 30 35 33 39 39 41 39 33 38 31 37 38 45 35 38 43 43 39 43 42 37 33 46 31 44 39 38 33 36 44 41 45 43 31 37 33 33 36 31 44 42 44 41 31 43 42 39 38 42 38 43 30 31 38 42 32 46 43 32 33 33 35 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {36 30 35 33 39 39 41 39 33 38 31 37 38 45 35 38 43 43 39 43 42 37 33 46 31 44 39 38 33 36 44 41 45 43 31 37 33 33 36 31 44 42 44 41 31 43 42 39 38 42 38 43 30 31 38 42 32 46 43 32 33 33 35 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\605399A938178E58CC9CB73F1D9836DAEC173361DBDA1CB98B8C018B2FC23352.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_GI_2147921817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.GI"
        threat_id = "2147921817"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:B093BC843B18EC65A664B83BB7AAE424FE36A17D8520591812D5BA940CC30E45" wide //weight: 1
        $x_1_2 = {42 30 39 33 42 43 38 34 33 42 31 38 45 43 36 35 41 36 36 34 42 38 33 42 42 37 41 41 45 34 32 34 46 45 33 36 41 31 37 44 38 35 32 30 35 39 31 38 31 32 44 35 42 41 39 34 30 43 43 33 30 45 34 35 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {42 30 39 33 42 43 38 34 33 42 31 38 45 43 36 35 41 36 36 34 42 38 33 42 42 37 41 41 45 34 32 34 46 45 33 36 41 31 37 44 38 35 32 30 35 39 31 38 31 32 44 35 42 41 39 34 30 43 43 33 30 45 34 35 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\B093BC843B18EC65A664B83BB7AAE424FE36A17D8520591812D5BA940CC30E45.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_GJ_2147921821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.GJ"
        threat_id = "2147921821"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:E230E1322C9C327955926CF965AF386914FA4F67A1516BE93CB7693CE4AC8009" wide //weight: 1
        $x_1_2 = {45 32 33 30 45 31 33 32 32 43 39 43 33 32 37 39 35 35 39 32 36 43 46 39 36 35 41 46 33 38 36 39 31 34 46 41 34 46 36 37 41 31 35 31 36 42 45 39 33 43 42 37 36 39 33 43 45 34 41 43 38 30 30 39 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {45 32 33 30 45 31 33 32 32 43 39 43 33 32 37 39 35 35 39 32 36 43 46 39 36 35 41 46 33 38 36 39 31 34 46 41 34 46 36 37 41 31 35 31 36 42 45 39 33 43 42 37 36 39 33 43 45 34 41 43 38 30 30 39 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\E230E1322C9C327955926CF965AF386914FA4F67A1516BE93CB7693CE4AC8009.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_GK_2147921825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.GK"
        threat_id = "2147921825"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:15F496730D19CBF0301FA08BAD9477F04FEEC4AE477C5AC4F164ABC8FC22F71D" wide //weight: 1
        $x_1_2 = {31 35 46 34 39 36 37 33 30 44 31 39 43 42 46 30 33 30 31 46 41 30 38 42 41 44 39 34 37 37 46 30 34 46 45 45 43 34 41 45 34 37 37 43 35 41 43 34 46 31 36 34 41 42 43 38 46 43 32 32 46 37 31 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {31 35 46 34 39 36 37 33 30 44 31 39 43 42 46 30 33 30 31 46 41 30 38 42 41 44 39 34 37 37 46 30 34 46 45 45 43 34 41 45 34 37 37 43 35 41 43 34 46 31 36 34 41 42 43 38 46 43 32 32 46 37 31 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\15F496730D19CBF0301FA08BAD9477F04FEEC4AE477C5AC4F164ABC8FC22F71D.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_GL_2147921829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.GL"
        threat_id = "2147921829"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:F934F9839465E92E23A755562178404F189D185EDBA96076865713FBD643E95E" wide //weight: 1
        $x_1_2 = {46 39 33 34 46 39 38 33 39 34 36 35 45 39 32 45 32 33 41 37 35 35 35 36 32 31 37 38 34 30 34 46 31 38 39 44 31 38 35 45 44 42 41 39 36 30 37 36 38 36 35 37 31 33 46 42 44 36 34 33 45 39 35 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {46 39 33 34 46 39 38 33 39 34 36 35 45 39 32 45 32 33 41 37 35 35 35 36 32 31 37 38 34 30 34 46 31 38 39 44 31 38 35 45 44 42 41 39 36 30 37 36 38 36 35 37 31 33 46 42 44 36 34 33 45 39 35 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\F934F9839465E92E23A755562178404F189D185EDBA96076865713FBD643E95E.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_GM_2147922182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.GM"
        threat_id = "2147922182"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:3797455B219CC74EB503399F0E70C57F19FC7BA58A5D36C80264FFA465A4FD21" wide //weight: 1
        $x_1_2 = {33 37 39 37 34 35 35 42 32 31 39 43 43 37 34 45 42 35 30 33 33 39 39 46 30 45 37 30 43 35 37 46 31 39 46 43 37 42 41 35 38 41 35 44 33 36 43 38 30 32 36 34 46 46 41 34 36 35 41 34 46 44 32 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {33 37 39 37 34 35 35 42 32 31 39 43 43 37 34 45 42 35 30 33 33 39 39 46 30 45 37 30 43 35 37 46 31 39 46 43 37 42 41 35 38 41 35 44 33 36 43 38 30 32 36 34 46 46 41 34 36 35 41 34 46 44 32 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\3797455B219CC74EB503399F0E70C57F19FC7BA58A5D36C80264FFA465A4FD21.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_GN_2147923355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.GN"
        threat_id = "2147923355"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:D7A5E0027572764BE600925712D079472FF950F954553FF07E823FF1D068C312" wide //weight: 1
        $x_1_2 = {44 37 41 35 45 30 30 32 37 35 37 32 37 36 34 42 45 36 30 30 39 32 35 37 31 32 44 30 37 39 34 37 32 46 46 39 35 30 46 39 35 34 35 35 33 46 46 30 37 45 38 32 33 46 46 31 44 30 36 38 43 33 31 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {44 37 41 35 45 30 30 32 37 35 37 32 37 36 34 42 45 36 30 30 39 32 35 37 31 32 44 30 37 39 34 37 32 46 46 39 35 30 46 39 35 34 35 35 33 46 46 30 37 45 38 32 33 46 46 31 44 30 36 38 43 33 31 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\D7A5E0027572764BE600925712D079472FF950F954553FF07E823FF1D068C312.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_GO_2147924542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.GO"
        threat_id = "2147924542"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:18EB92BD6E4B55B60CC913088F952B7123D0612A5FCE67C2EDF40AAB687E2904" wide //weight: 1
        $x_1_2 = {31 38 45 42 39 32 42 44 36 45 34 42 35 35 42 36 30 43 43 39 31 33 30 38 38 46 39 35 32 42 37 31 32 33 44 30 36 31 32 41 35 46 43 45 36 37 43 32 45 44 46 34 30 41 41 42 36 38 37 45 32 39 30 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {31 38 45 42 39 32 42 44 36 45 34 42 35 35 42 36 30 43 43 39 31 33 30 38 38 46 39 35 32 42 37 31 32 33 44 30 36 31 32 41 35 46 43 45 36 37 43 32 45 44 46 34 30 41 41 42 36 38 37 45 32 39 30 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\18EB92BD6E4B55B60CC913088F952B7123D0612A5FCE67C2EDF40AAB687E2904.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_GP_2147924546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.GP"
        threat_id = "2147924546"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:8C3995AF7ACD721D8180C19A2C41E7D46C51049BE1871F5784864178BBC18B08" wide //weight: 1
        $x_1_2 = {38 43 33 39 39 35 41 46 37 41 43 44 37 32 31 44 38 31 38 30 43 31 39 41 32 43 34 31 45 37 44 34 36 43 35 31 30 34 39 42 45 31 38 37 31 46 35 37 38 34 38 36 34 31 37 38 42 42 43 31 38 42 30 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {38 43 33 39 39 35 41 46 37 41 43 44 37 32 31 44 38 31 38 30 43 31 39 41 32 43 34 31 45 37 44 34 36 43 35 31 30 34 39 42 45 31 38 37 31 46 35 37 38 34 38 36 34 31 37 38 42 42 43 31 38 42 30 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\8C3995AF7ACD721D8180C19A2C41E7D46C51049BE1871F5784864178BBC18B08.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_GQ_2147924770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.GQ"
        threat_id = "2147924770"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:EF404FB3FC9AC9032A868ED87493D2946D96EFA83DFC6184053CA8289A27FC6C" wide //weight: 1
        $x_1_2 = {45 46 34 30 34 46 42 33 46 43 39 41 43 39 30 33 32 41 38 36 38 45 44 38 37 34 39 33 44 32 39 34 36 44 39 36 45 46 41 38 33 44 46 43 36 31 38 34 30 35 33 43 41 38 32 38 39 41 32 37 46 43 36 43 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {45 46 34 30 34 46 42 33 46 43 39 41 43 39 30 33 32 41 38 36 38 45 44 38 37 34 39 33 44 32 39 34 36 44 39 36 45 46 41 38 33 44 46 43 36 31 38 34 30 35 33 43 41 38 32 38 39 41 32 37 46 43 36 43 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\EF404FB3FC9AC9032A868ED87493D2946D96EFA83DFC6184053CA8289A27FC6C.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_GR_2147924901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.GR"
        threat_id = "2147924901"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:94D11E694A924ECB88D42C2A6412BC980C2744B5FFF784EE6097416C98D97461" wide //weight: 1
        $x_1_2 = {39 34 44 31 31 45 36 39 34 41 39 32 34 45 43 42 38 38 44 34 32 43 32 41 36 34 31 32 42 43 39 38 30 43 32 37 34 34 42 35 46 46 46 37 38 34 45 45 36 30 39 37 34 31 36 43 39 38 44 39 37 34 36 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {39 34 44 31 31 45 36 39 34 41 39 32 34 45 43 42 38 38 44 34 32 43 32 41 36 34 31 32 42 43 39 38 30 43 32 37 34 34 42 35 46 46 46 37 38 34 45 45 36 30 39 37 34 31 36 43 39 38 44 39 37 34 36 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\94D11E694A924ECB88D42C2A6412BC980C2744B5FFF784EE6097416C98D97461.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_GS_2147925087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.GS"
        threat_id = "2147925087"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:14F335E436E62F32720218B99A9DB77EE69AEC3AC8CBEAB0D68CEE67BE89A930" wide //weight: 1
        $x_1_2 = {31 34 46 33 33 35 45 34 33 36 45 36 32 46 33 32 37 32 30 32 31 38 42 39 39 41 39 44 42 37 37 45 45 36 39 41 45 43 33 41 43 38 43 42 45 41 42 30 44 36 38 43 45 45 36 37 42 45 38 39 41 39 33 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {31 34 46 33 33 35 45 34 33 36 45 36 32 46 33 32 37 32 30 32 31 38 42 39 39 41 39 44 42 37 37 45 45 36 39 41 45 43 33 41 43 38 43 42 45 41 42 30 44 36 38 43 45 45 36 37 42 45 38 39 41 39 33 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\14F335E436E62F32720218B99A9DB77EE69AEC3AC8CBEAB0D68CEE67BE89A930.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_GT_2147925703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.GT"
        threat_id = "2147925703"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:28A28E8137979256397197744C175BDAB423B3D05C49E49D2F4C94FE06924310" wide //weight: 1
        $x_1_2 = {32 38 41 32 38 45 38 31 33 37 39 37 39 32 35 36 33 39 37 31 39 37 37 34 34 43 31 37 35 42 44 41 42 34 32 33 42 33 44 30 35 43 34 39 45 34 39 44 32 46 34 43 39 34 46 45 30 36 39 32 34 33 31 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {32 38 41 32 38 45 38 31 33 37 39 37 39 32 35 36 33 39 37 31 39 37 37 34 34 43 31 37 35 42 44 41 42 34 32 33 42 33 44 30 35 43 34 39 45 34 39 44 32 46 34 43 39 34 46 45 30 36 39 32 34 33 31 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\28A28E8137979256397197744C175BDAB423B3D05C49E49D2F4C94FE06924310.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_GU_2147925707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.GU"
        threat_id = "2147925707"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:898923FE0699CFE1EFD17773425DECB080840877C29F883D389D6880B2B96173" wide //weight: 1
        $x_1_2 = {38 39 38 39 32 33 46 45 30 36 39 39 43 46 45 31 45 46 44 31 37 37 37 33 34 32 35 44 45 43 42 30 38 30 38 34 30 38 37 37 43 32 39 46 38 38 33 44 33 38 39 44 36 38 38 30 42 32 42 39 36 31 37 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {38 39 38 39 32 33 46 45 30 36 39 39 43 46 45 31 45 46 44 31 37 37 37 33 34 32 35 44 45 43 42 30 38 30 38 34 30 38 37 37 43 32 39 46 38 38 33 44 33 38 39 44 36 38 38 30 42 32 42 39 36 31 37 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\898923FE0699CFE1EFD17773425DECB080840877C29F883D389D6880B2B96173.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_GV_2147925711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.GV"
        threat_id = "2147925711"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:19A549A57160F384CF4E36EE1A24747ED99C623C48EA545F343296FB7092795D" wide //weight: 1
        $x_1_2 = {31 39 41 35 34 39 41 35 37 31 36 30 46 33 38 34 43 46 34 45 33 36 45 45 31 41 32 34 37 34 37 45 44 39 39 43 36 32 33 43 34 38 45 41 35 34 35 46 33 34 33 32 39 36 46 42 37 30 39 32 37 39 35 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {31 39 41 35 34 39 41 35 37 31 36 30 46 33 38 34 43 46 34 45 33 36 45 45 31 41 32 34 37 34 37 45 44 39 39 43 36 32 33 43 34 38 45 41 35 34 35 46 33 34 33 32 39 36 46 42 37 30 39 32 37 39 35 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\19A549A57160F384CF4E36EE1A24747ED99C623C48EA545F343296FB7092795D.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_GW_2147926791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.GW"
        threat_id = "2147926791"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:DB6E39D48AEF442A219248F82B2C101FFFCA7DADA77CD9BDE31C886FDECFFB58" wide //weight: 1
        $x_1_2 = {44 42 36 45 33 39 44 34 38 41 45 46 34 34 32 41 32 31 39 32 34 38 46 38 32 42 32 43 31 30 31 46 46 46 43 41 37 44 41 44 41 37 37 43 44 39 42 44 45 33 31 43 38 38 36 46 44 45 43 46 46 42 35 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {44 42 36 45 33 39 44 34 38 41 45 46 34 34 32 41 32 31 39 32 34 38 46 38 32 42 32 43 31 30 31 46 46 46 43 41 37 44 41 44 41 37 37 43 44 39 42 44 45 33 31 43 38 38 36 46 44 45 43 46 46 42 35 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\DB6E39D48AEF442A219248F82B2C101FFFCA7DADA77CD9BDE31C886FDECFFB58.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_GX_2147926992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.GX"
        threat_id = "2147926992"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:D29B43234FD74DC8383AAEA2BDAB5CBE95BA290B930F631E2C65573201A7FD12" wide //weight: 1
        $x_1_2 = {44 32 39 42 34 33 32 33 34 46 44 37 34 44 43 38 33 38 33 41 41 45 41 32 42 44 41 42 35 43 42 45 39 35 42 41 32 39 30 42 39 33 30 46 36 33 31 45 32 43 36 35 35 37 33 32 30 31 41 37 46 44 31 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {44 32 39 42 34 33 32 33 34 46 44 37 34 44 43 38 33 38 33 41 41 45 41 32 42 44 41 42 35 43 42 45 39 35 42 41 32 39 30 42 39 33 30 46 36 33 31 45 32 43 36 35 35 37 33 32 30 31 41 37 46 44 31 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\D29B43234FD74DC8383AAEA2BDAB5CBE95BA290B930F631E2C65573201A7FD12.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_GY_2147928547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.GY"
        threat_id = "2147928547"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:320D6F294A59A1F5AD586599F21058E279929F9D2B4B6C64A3A1789E7FF4C819" wide //weight: 1
        $x_1_2 = {33 32 30 44 36 46 32 39 34 41 35 39 41 31 46 35 41 44 35 38 36 35 39 39 46 32 31 30 35 38 45 32 37 39 39 32 39 46 39 44 32 42 34 42 36 43 36 34 41 33 41 31 37 38 39 45 37 46 46 34 43 38 31 39 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {33 32 30 44 36 46 32 39 34 41 35 39 41 31 46 35 41 44 35 38 36 35 39 39 46 32 31 30 35 38 45 32 37 39 39 32 39 46 39 44 32 42 34 42 36 43 36 34 41 33 41 31 37 38 39 45 37 46 46 34 43 38 31 39 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\320D6F294A59A1F5AD586599F21058E279929F9D2B4B6C64A3A1789E7FF4C819.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_GZ_2147929639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.GZ"
        threat_id = "2147929639"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:EAF10F898A86588D593D442A596117983178A7A6ED27882486D7D9C4F8750B3D" wide //weight: 1
        $x_1_2 = {45 41 46 31 30 46 38 39 38 41 38 36 35 38 38 44 35 39 33 44 34 34 32 41 35 39 36 31 31 37 39 38 33 31 37 38 41 37 41 36 45 44 32 37 38 38 32 34 38 36 44 37 44 39 43 34 46 38 37 35 30 42 33 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {45 41 46 31 30 46 38 39 38 41 38 36 35 38 38 44 35 39 33 44 34 34 32 41 35 39 36 31 31 37 39 38 33 31 37 38 41 37 41 36 45 44 32 37 38 38 32 34 38 36 44 37 44 39 43 34 46 38 37 35 30 42 33 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\EAF10F898A86588D593D442A596117983178A7A6ED27882486D7D9C4F8750B3D.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_HA_2147929738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.HA"
        threat_id = "2147929738"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:AE1C5E273C1B6DDE068DC57B10A7023591C910D1FAAA16E40593D0EEBBD0BE30" wide //weight: 1
        $x_1_2 = {41 45 31 43 35 45 32 37 33 43 31 42 36 44 44 45 30 36 38 44 43 35 37 42 31 30 41 37 30 32 33 35 39 31 43 39 31 30 44 31 46 41 41 41 31 36 45 34 30 35 39 33 44 30 45 45 42 42 44 30 42 45 33 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {41 45 31 43 35 45 32 37 33 43 31 42 36 44 44 45 30 36 38 44 43 35 37 42 31 30 41 37 30 32 33 35 39 31 43 39 31 30 44 31 46 41 41 41 31 36 45 34 30 35 39 33 44 30 45 45 42 42 44 30 42 45 33 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\AE1C5E273C1B6DDE068DC57B10A7023591C910D1FAAA16E40593D0EEBBD0BE30.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_HB_2147930222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.HB"
        threat_id = "2147930222"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:FC5AF6BC0F44FFA33A962DDBB3DECE9115BB2080007A8AA13C6A598237D67F16" wide //weight: 1
        $x_1_2 = {46 43 35 41 46 36 42 43 30 46 34 34 46 46 41 33 33 41 39 36 32 44 44 42 42 33 44 45 43 45 39 31 31 35 42 42 32 30 38 30 30 30 37 41 38 41 41 31 33 43 36 41 35 39 38 32 33 37 44 36 37 46 31 36 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {46 43 35 41 46 36 42 43 30 46 34 34 46 46 41 33 33 41 39 36 32 44 44 42 42 33 44 45 43 45 39 31 31 35 42 42 32 30 38 30 30 30 37 41 38 41 41 31 33 43 36 41 35 39 38 32 33 37 44 36 37 46 31 36 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\FC5AF6BC0F44FFA33A962DDBB3DECE9115BB2080007A8AA13C6A598237D67F16.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_HC_2147931625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.HC"
        threat_id = "2147931625"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:20A32ABC1E4EC6D53861D7202E730501EE5E950EB1FE96A0CADB7C231F44C959" wide //weight: 1
        $x_1_2 = {32 30 41 33 32 41 42 43 31 45 34 45 43 36 44 35 33 38 36 31 44 37 32 30 32 45 37 33 30 35 30 31 45 45 35 45 39 35 30 45 42 31 46 45 39 36 41 30 43 41 44 42 37 43 32 33 31 46 34 34 43 39 35 39 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {32 30 41 33 32 41 42 43 31 45 34 45 43 36 44 35 33 38 36 31 44 37 32 30 32 45 37 33 30 35 30 31 45 45 35 45 39 35 30 45 42 31 46 45 39 36 41 30 43 41 44 42 37 43 32 33 31 46 34 34 43 39 35 39 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\20A32ABC1E4EC6D53861D7202E730501EE5E950EB1FE96A0CADB7C231F44C959.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_HD_2147931629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.HD"
        threat_id = "2147931629"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:34BA12E4BE532885BAD25BDC4EFA0BCC4145B76B58A90E0C4E2A80D37A5A9F30" wide //weight: 1
        $x_1_2 = {33 34 42 41 31 32 45 34 42 45 35 33 32 38 38 35 42 41 44 32 35 42 44 43 34 45 46 41 30 42 43 43 34 31 34 35 42 37 36 42 35 38 41 39 30 45 30 43 34 45 32 41 38 30 44 33 37 41 35 41 39 46 33 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {33 34 42 41 31 32 45 34 42 45 35 33 32 38 38 35 42 41 44 32 35 42 44 43 34 45 46 41 30 42 43 43 34 31 34 35 42 37 36 42 35 38 41 39 30 45 30 43 34 45 32 41 38 30 44 33 37 41 35 41 39 46 33 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\34BA12E4BE532885BAD25BDC4EFA0BCC4145B76B58A90E0C4E2A80D37A5A9F30.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_HE_2147931633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.HE"
        threat_id = "2147931633"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:D10202E688A76AAFA8B41BADB1354B8EA0CDB1A5CBEBDABDAEE4375509B8E371" wide //weight: 1
        $x_1_2 = {44 31 30 32 30 32 45 36 38 38 41 37 36 41 41 46 41 38 42 34 31 42 41 44 42 31 33 35 34 42 38 45 41 30 43 44 42 31 41 35 43 42 45 42 44 41 42 44 41 45 45 34 33 37 35 35 30 39 42 38 45 33 37 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {44 31 30 32 30 32 45 36 38 38 41 37 36 41 41 46 41 38 42 34 31 42 41 44 42 31 33 35 34 42 38 45 41 30 43 44 42 31 41 35 43 42 45 42 44 41 42 44 41 45 45 34 33 37 35 35 30 39 42 38 45 33 37 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\D10202E688A76AAFA8B41BADB1354B8EA0CDB1A5CBEBDABDAEE4375509B8E371.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_HF_2147931637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.HF"
        threat_id = "2147931637"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:0A79401ECEB69C74FD9831002B97635A13BFDF90C33A83A8EE7014199B1ED05B" wide //weight: 1
        $x_1_2 = {30 41 37 39 34 30 31 45 43 45 42 36 39 43 37 34 46 44 39 38 33 31 30 30 32 42 39 37 36 33 35 41 31 33 42 46 44 46 39 30 43 33 33 41 38 33 41 38 45 45 37 30 31 34 31 39 39 42 31 45 44 30 35 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {30 41 37 39 34 30 31 45 43 45 42 36 39 43 37 34 46 44 39 38 33 31 30 30 32 42 39 37 36 33 35 41 31 33 42 46 44 46 39 30 43 33 33 41 38 33 41 38 45 45 37 30 31 34 31 39 39 42 31 45 44 30 35 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\0A79401ECEB69C74FD9831002B97635A13BFDF90C33A83A8EE7014199B1ED05B.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_HG_2147931641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.HG"
        threat_id = "2147931641"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:64C2EB66670181B9057E8FD4299032EA89599943E7D36A508CB9DC9CB0513126" wide //weight: 1
        $x_1_2 = {36 34 43 32 45 42 36 36 36 37 30 31 38 31 42 39 30 35 37 45 38 46 44 34 32 39 39 30 33 32 45 41 38 39 35 39 39 39 34 33 45 37 44 33 36 41 35 30 38 43 42 39 44 43 39 43 42 30 35 31 33 31 32 36 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {36 34 43 32 45 42 36 36 36 37 30 31 38 31 42 39 30 35 37 45 38 46 44 34 32 39 39 30 33 32 45 41 38 39 35 39 39 39 34 33 45 37 44 33 36 41 35 30 38 43 42 39 44 43 39 43 42 30 35 31 33 31 32 36 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\64C2EB66670181B9057E8FD4299032EA89599943E7D36A508CB9DC9CB0513126.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_HH_2147931645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.HH"
        threat_id = "2147931645"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:AA4D0D135044A1A35A00BF24E453EC93702B5B0279935B9F709E76A155236630" wide //weight: 1
        $x_1_2 = {41 41 34 44 30 44 31 33 35 30 34 34 41 31 41 33 35 41 30 30 42 46 32 34 45 34 35 33 45 43 39 33 37 30 32 42 35 42 30 32 37 39 39 33 35 42 39 46 37 30 39 45 37 36 41 31 35 35 32 33 36 36 33 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {41 41 34 44 30 44 31 33 35 30 34 34 41 31 41 33 35 41 30 30 42 46 32 34 45 34 35 33 45 43 39 33 37 30 32 42 35 42 30 32 37 39 39 33 35 42 39 46 37 30 39 45 37 36 41 31 35 35 32 33 36 36 33 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\AA4D0D135044A1A35A00BF24E453EC93702B5B0279935B9F709E76A155236630.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_HI_2147931649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.HI"
        threat_id = "2147931649"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:D48F8A0B1CE7181EE010FC85EEA0CA92D191A42163A1029C37C04B0BB5A71637" wide //weight: 1
        $x_1_2 = {44 34 38 46 38 41 30 42 31 43 45 37 31 38 31 45 45 30 31 30 46 43 38 35 45 45 41 30 43 41 39 32 44 31 39 31 41 34 32 31 36 33 41 31 30 32 39 43 33 37 43 30 34 42 30 42 42 35 41 37 31 36 33 37 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {44 34 38 46 38 41 30 42 31 43 45 37 31 38 31 45 45 30 31 30 46 43 38 35 45 45 41 30 43 41 39 32 44 31 39 31 41 34 32 31 36 33 41 31 30 32 39 43 33 37 43 30 34 42 30 42 42 35 41 37 31 36 33 37 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\D48F8A0B1CE7181EE010FC85EEA0CA92D191A42163A1029C37C04B0BB5A71637.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_HJ_2147931653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.HJ"
        threat_id = "2147931653"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:E4037039EB2D2F52A2B29E783C52FF6FC0E4D29D38611111C19A5E300F82FB0E" wide //weight: 1
        $x_1_2 = {45 34 30 33 37 30 33 39 45 42 32 44 32 46 35 32 41 32 42 32 39 45 37 38 33 43 35 32 46 46 36 46 43 30 45 34 44 32 39 44 33 38 36 31 31 31 31 31 43 31 39 41 35 45 33 30 30 46 38 32 46 42 30 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {45 34 30 33 37 30 33 39 45 42 32 44 32 46 35 32 41 32 42 32 39 45 37 38 33 43 35 32 46 46 36 46 43 30 45 34 44 32 39 44 33 38 36 31 31 31 31 31 43 31 39 41 35 45 33 30 30 46 38 32 46 42 30 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\E4037039EB2D2F52A2B29E783C52FF6FC0E4D29D38611111C19A5E300F82FB0E.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_HK_2147931831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.HK"
        threat_id = "2147931831"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:07BF3802C93C42739CFD0328A830801C7182C73D2FFC28E76681C6EFFC85A478" wide //weight: 1
        $x_1_2 = {30 37 42 46 33 38 30 32 43 39 33 43 34 32 37 33 39 43 46 44 30 33 32 38 41 38 33 30 38 30 31 43 37 31 38 32 43 37 33 44 32 46 46 43 32 38 45 37 36 36 38 31 43 36 45 46 46 43 38 35 41 34 37 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {30 37 42 46 33 38 30 32 43 39 33 43 34 32 37 33 39 43 46 44 30 33 32 38 41 38 33 30 38 30 31 43 37 31 38 32 43 37 33 44 32 46 46 43 32 38 45 37 36 36 38 31 43 36 45 46 46 43 38 35 41 34 37 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\07BF3802C93C42739CFD0328A830801C7182C73D2FFC28E76681C6EFFC85A478.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_HL_2147931835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.HL"
        threat_id = "2147931835"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:204E91D375BADE81DC528EFCC105A5D046DB92FCC4B75F08E151053DCD8D5025" wide //weight: 1
        $x_1_2 = {32 30 34 45 39 31 44 33 37 35 42 41 44 45 38 31 44 43 35 32 38 45 46 43 43 31 30 35 41 35 44 30 34 36 44 42 39 32 46 43 43 34 42 37 35 46 30 38 45 31 35 31 30 35 33 44 43 44 38 44 35 30 32 35 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {32 30 34 45 39 31 44 33 37 35 42 41 44 45 38 31 44 43 35 32 38 45 46 43 43 31 30 35 41 35 44 30 34 36 44 42 39 32 46 43 43 34 42 37 35 46 30 38 45 31 35 31 30 35 33 44 43 44 38 44 35 30 32 35 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\204E91D375BADE81DC528EFCC105A5D046DB92FCC4B75F08E151053DCD8D5025.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_HM_2147931839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.HM"
        threat_id = "2147931839"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:284AFB03BA5BF6D13B3E92B5111E16F5140255075AC0C2775698965895AC5A7D" wide //weight: 1
        $x_1_2 = {32 38 34 41 46 42 30 33 42 41 35 42 46 36 44 31 33 42 33 45 39 32 42 35 31 31 31 45 31 36 46 35 31 34 30 32 35 35 30 37 35 41 43 30 43 32 37 37 35 36 39 38 39 36 35 38 39 35 41 43 35 41 37 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {32 38 34 41 46 42 30 33 42 41 35 42 46 36 44 31 33 42 33 45 39 32 42 35 31 31 31 45 31 36 46 35 31 34 30 32 35 35 30 37 35 41 43 30 43 32 37 37 35 36 39 38 39 36 35 38 39 35 41 43 35 41 37 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\284AFB03BA5BF6D13B3E92B5111E16F5140255075AC0C2775698965895AC5A7D.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_HN_2147931843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.HN"
        threat_id = "2147931843"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:37070FA85465C92677007577543F09C5B67F8211CCF2C16660D40F94B6847C4A" wide //weight: 1
        $x_1_2 = {33 37 30 37 30 46 41 38 35 34 36 35 43 39 32 36 37 37 30 30 37 35 37 37 35 34 33 46 30 39 43 35 42 36 37 46 38 32 31 31 43 43 46 32 43 31 36 36 36 30 44 34 30 46 39 34 42 36 38 34 37 43 34 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {33 37 30 37 30 46 41 38 35 34 36 35 43 39 32 36 37 37 30 30 37 35 37 37 35 34 33 46 30 39 43 35 42 36 37 46 38 32 31 31 43 43 46 32 43 31 36 36 36 30 44 34 30 46 39 34 42 36 38 34 37 43 34 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\37070FA85465C92677007577543F09C5B67F8211CCF2C16660D40F94B6847C4A.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_HO_2147931847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.HO"
        threat_id = "2147931847"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:3CC7CCEF369D6A7A4F6CAD11D12D7DE671909962944A7D034282F1F7B54F9D35" wide //weight: 1
        $x_1_2 = {33 43 43 37 43 43 45 46 33 36 39 44 36 41 37 41 34 46 36 43 41 44 31 31 44 31 32 44 37 44 45 36 37 31 39 30 39 39 36 32 39 34 34 41 37 44 30 33 34 32 38 32 46 31 46 37 42 35 34 46 39 44 33 35 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {33 43 43 37 43 43 45 46 33 36 39 44 36 41 37 41 34 46 36 43 41 44 31 31 44 31 32 44 37 44 45 36 37 31 39 30 39 39 36 32 39 34 34 41 37 44 30 33 34 32 38 32 46 31 46 37 42 35 34 46 39 44 33 35 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\3CC7CCEF369D6A7A4F6CAD11D12D7DE671909962944A7D034282F1F7B54F9D35.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_HP_2147931851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.HP"
        threat_id = "2147931851"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:57309B4FFB75A04AAAE491451CA128035B78C22AF220F24BDA3CFE0D393ACC18" wide //weight: 1
        $x_1_2 = {35 37 33 30 39 42 34 46 46 42 37 35 41 30 34 41 41 41 45 34 39 31 34 35 31 43 41 31 32 38 30 33 35 42 37 38 43 32 32 41 46 32 32 30 46 32 34 42 44 41 33 43 46 45 30 44 33 39 33 41 43 43 31 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {35 37 33 30 39 42 34 46 46 42 37 35 41 30 34 41 41 41 45 34 39 31 34 35 31 43 41 31 32 38 30 33 35 42 37 38 43 32 32 41 46 32 32 30 46 32 34 42 44 41 33 43 46 45 30 44 33 39 33 41 43 43 31 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\57309B4FFB75A04AAAE491451CA128035B78C22AF220F24BDA3CFE0D393ACC18.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_HQ_2147931855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.HQ"
        threat_id = "2147931855"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:6A301ED6E5D3435A3086C99E892F03DD2322D38737A59AE7B2A0E57FC341D967" wide //weight: 1
        $x_1_2 = {36 41 33 30 31 45 44 36 45 35 44 33 34 33 35 41 33 30 38 36 43 39 39 45 38 39 32 46 30 33 44 44 32 33 32 32 44 33 38 37 33 37 41 35 39 41 45 37 42 32 41 30 45 35 37 46 43 33 34 31 44 39 36 37 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {36 41 33 30 31 45 44 36 45 35 44 33 34 33 35 41 33 30 38 36 43 39 39 45 38 39 32 46 30 33 44 44 32 33 32 32 44 33 38 37 33 37 41 35 39 41 45 37 42 32 41 30 45 35 37 46 43 33 34 31 44 39 36 37 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\6A301ED6E5D3435A3086C99E892F03DD2322D38737A59AE7B2A0E57FC341D967.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_HR_2147931859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.HR"
        threat_id = "2147931859"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:6ACB63BA5CE3181B447E9865418497D258550BD88828D460333207EB5BD38D7F" wide //weight: 1
        $x_1_2 = {36 41 43 42 36 33 42 41 35 43 45 33 31 38 31 42 34 34 37 45 39 38 36 35 34 31 38 34 39 37 44 32 35 38 35 35 30 42 44 38 38 38 32 38 44 34 36 30 33 33 33 32 30 37 45 42 35 42 44 33 38 44 37 46 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {36 41 43 42 36 33 42 41 35 43 45 33 31 38 31 42 34 34 37 45 39 38 36 35 34 31 38 34 39 37 44 32 35 38 35 35 30 42 44 38 38 38 32 38 44 34 36 30 33 33 33 32 30 37 45 42 35 42 44 33 38 44 37 46 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\6ACB63BA5CE3181B447E9865418497D258550BD88828D460333207EB5BD38D7F.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_HS_2147931863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.HS"
        threat_id = "2147931863"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:B86FC08132BB71B087740EFA1BE61E3E03117C76E21473F7A4BBAD2FC0FEAA13" wide //weight: 1
        $x_1_2 = {42 38 36 46 43 30 38 31 33 32 42 42 37 31 42 30 38 37 37 34 30 45 46 41 31 42 45 36 31 45 33 45 30 33 31 31 37 43 37 36 45 32 31 34 37 33 46 37 41 34 42 42 41 44 32 46 43 30 46 45 41 41 31 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {42 38 36 46 43 30 38 31 33 32 42 42 37 31 42 30 38 37 37 34 30 45 46 41 31 42 45 36 31 45 33 45 30 33 31 31 37 43 37 36 45 32 31 34 37 33 46 37 41 34 42 42 41 44 32 46 43 30 46 45 41 41 31 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\B86FC08132BB71B087740EFA1BE61E3E03117C76E21473F7A4BBAD2FC0FEAA13.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_HT_2147931867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.HT"
        threat_id = "2147931867"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:E547F7D79733C2C43ACEF824A3208043DEF9F2C372604F662B4BFAEE480FE779" wide //weight: 1
        $x_1_2 = {45 35 34 37 46 37 44 37 39 37 33 33 43 32 43 34 33 41 43 45 46 38 32 34 41 33 32 30 38 30 34 33 44 45 46 39 46 32 43 33 37 32 36 30 34 46 36 36 32 42 34 42 46 41 45 45 34 38 30 46 45 37 37 39 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {45 35 34 37 46 37 44 37 39 37 33 33 43 32 43 34 33 41 43 45 46 38 32 34 41 33 32 30 38 30 34 33 44 45 46 39 46 32 43 33 37 32 36 30 34 46 36 36 32 42 34 42 46 41 45 45 34 38 30 46 45 37 37 39 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\E547F7D79733C2C43ACEF824A3208043DEF9F2C372604F662B4BFAEE480FE779.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_HU_2147932097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.HU"
        threat_id = "2147932097"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:061AA6BDE8F6DE6C92F0D6E077359BF6911FCAF80030E82B3A3DB65E63C80113" wide //weight: 1
        $x_1_2 = {30 36 31 41 41 36 42 44 45 38 46 36 44 45 36 43 39 32 46 30 44 36 45 30 37 37 33 35 39 42 46 36 39 31 31 46 43 41 46 38 30 30 33 30 45 38 32 42 33 41 33 44 42 36 35 45 36 33 43 38 30 31 31 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {30 36 31 41 41 36 42 44 45 38 46 36 44 45 36 43 39 32 46 30 44 36 45 30 37 37 33 35 39 42 46 36 39 31 31 46 43 41 46 38 30 30 33 30 45 38 32 42 33 41 33 44 42 36 35 45 36 33 43 38 30 31 31 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\061AA6BDE8F6DE6C92F0D6E077359BF6911FCAF80030E82B3A3DB65E63C80113.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_HV_2147932101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.HV"
        threat_id = "2147932101"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:D671ACD243E7B93732A54D09CCE7A41B59F3D655AA01CB94CFDB3E16A1ACFB02" wide //weight: 1
        $x_1_2 = {44 36 37 31 41 43 44 32 34 33 45 37 42 39 33 37 33 32 41 35 34 44 30 39 43 43 45 37 41 34 31 42 35 39 46 33 44 36 35 35 41 41 30 31 43 42 39 34 43 46 44 42 33 45 31 36 41 31 41 43 46 42 30 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {44 36 37 31 41 43 44 32 34 33 45 37 42 39 33 37 33 32 41 35 34 44 30 39 43 43 45 37 41 34 31 42 35 39 46 33 44 36 35 35 41 41 30 31 43 42 39 34 43 46 44 42 33 45 31 36 41 31 41 43 46 42 30 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\D671ACD243E7B93732A54D09CCE7A41B59F3D655AA01CB94CFDB3E16A1ACFB02.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_HW_2147932105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.HW"
        threat_id = "2147932105"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:E269EA3B12BB0FC371E63700D4458E0465497A67D8B933B3D797454C02AB390C" wide //weight: 1
        $x_1_2 = {45 32 36 39 45 41 33 42 31 32 42 42 30 46 43 33 37 31 45 36 33 37 30 30 44 34 34 35 38 45 30 34 36 35 34 39 37 41 36 37 44 38 42 39 33 33 42 33 44 37 39 37 34 35 34 43 30 32 41 42 33 39 30 43 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {45 32 36 39 45 41 33 42 31 32 42 42 30 46 43 33 37 31 45 36 33 37 30 30 44 34 34 35 38 45 30 34 36 35 34 39 37 41 36 37 44 38 42 39 33 33 42 33 44 37 39 37 34 35 34 43 30 32 41 42 33 39 30 43 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\E269EA3B12BB0FC371E63700D4458E0465497A67D8B933B3D797454C02AB390C.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_HX_2147932109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.HX"
        threat_id = "2147932109"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:6AC5E4FF4999D889C1349A1964F2FCD639FCD4023E4D57673072FB1E6232221C" wide //weight: 1
        $x_1_2 = {36 41 43 35 45 34 46 46 34 39 39 39 44 38 38 39 43 31 33 34 39 41 31 39 36 34 46 32 46 43 44 36 33 39 46 43 44 34 30 32 33 45 34 44 35 37 36 37 33 30 37 32 46 42 31 45 36 32 33 32 32 32 31 43 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {36 41 43 35 45 34 46 46 34 39 39 39 44 38 38 39 43 31 33 34 39 41 31 39 36 34 46 32 46 43 44 36 33 39 46 43 44 34 30 32 33 45 34 44 35 37 36 37 33 30 37 32 46 42 31 45 36 32 33 32 32 32 31 43 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\6AC5E4FF4999D889C1349A1964F2FCD639FCD4023E4D57673072FB1E6232221C.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_HY_2147932113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.HY"
        threat_id = "2147932113"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:7F7CF80A00593E5A789523299A0A1AB6CBFB472EC3A3FD9BFC7B01922A98C30C" wide //weight: 1
        $x_1_2 = {37 46 37 43 46 38 30 41 30 30 35 39 33 45 35 41 37 38 39 35 32 33 32 39 39 41 30 41 31 41 42 36 43 42 46 42 34 37 32 45 43 33 41 33 46 44 39 42 46 43 37 42 30 31 39 32 32 41 39 38 43 33 30 43 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {37 46 37 43 46 38 30 41 30 30 35 39 33 45 35 41 37 38 39 35 32 33 32 39 39 41 30 41 31 41 42 36 43 42 46 42 34 37 32 45 43 33 41 33 46 44 39 42 46 43 37 42 30 31 39 32 32 41 39 38 43 33 30 43 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\7F7CF80A00593E5A789523299A0A1AB6CBFB472EC3A3FD9BFC7B01922A98C30C.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_HZ_2147932537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.HZ"
        threat_id = "2147932537"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:28F633BF7F6E7E5E97726FF65F0A268F219468A35EA14B00F2A728CE66D54D34" wide //weight: 1
        $x_1_2 = {32 38 46 36 33 33 42 46 37 46 36 45 37 45 35 45 39 37 37 32 36 46 46 36 35 46 30 41 32 36 38 46 32 31 39 34 36 38 41 33 35 45 41 31 34 42 30 30 46 32 41 37 32 38 43 45 36 36 44 35 34 44 33 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {32 38 46 36 33 33 42 46 37 46 36 45 37 45 35 45 39 37 37 32 36 46 46 36 35 46 30 41 32 36 38 46 32 31 39 34 36 38 41 33 35 45 41 31 34 42 30 30 46 32 41 37 32 38 43 45 36 36 44 35 34 44 33 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\28F633BF7F6E7E5E97726FF65F0A268F219468A35EA14B00F2A728CE66D54D34.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_IA_2147932541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.IA"
        threat_id = "2147932541"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:6D8560C20E277B28E7C290A678F891F1D2FB32402C0AE80DA18CB2C06F94F644" wide //weight: 1
        $x_1_2 = {36 44 38 35 36 30 43 32 30 45 32 37 37 42 32 38 45 37 43 32 39 30 41 36 37 38 46 38 39 31 46 31 44 32 46 42 33 32 34 30 32 43 30 41 45 38 30 44 41 31 38 43 42 32 43 30 36 46 39 34 46 36 34 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {36 44 38 35 36 30 43 32 30 45 32 37 37 42 32 38 45 37 43 32 39 30 41 36 37 38 46 38 39 31 46 31 44 32 46 42 33 32 34 30 32 43 30 41 45 38 30 44 41 31 38 43 42 32 43 30 36 46 39 34 46 36 34 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\6D8560C20E277B28E7C290A678F891F1D2FB32402C0AE80DA18CB2C06F94F644.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_IB_2147933135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.IB"
        threat_id = "2147933135"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:ADA6E26332F26451E45768179C771CA87A7F0F4E234DA8D882888F505494925D" wide //weight: 1
        $x_1_2 = {41 44 41 36 45 32 36 33 33 32 46 32 36 34 35 31 45 34 35 37 36 38 31 37 39 43 37 37 31 43 41 38 37 41 37 46 30 46 34 45 32 33 34 44 41 38 44 38 38 32 38 38 38 46 35 30 35 34 39 34 39 32 35 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {41 44 41 36 45 32 36 33 33 32 46 32 36 34 35 31 45 34 35 37 36 38 31 37 39 43 37 37 31 43 41 38 37 41 37 46 30 46 34 45 32 33 34 44 41 38 44 38 38 32 38 38 38 46 35 30 35 34 39 34 39 32 35 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\ADA6E26332F26451E45768179C771CA87A7F0F4E234DA8D882888F505494925D.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_IC_2147933139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.IC"
        threat_id = "2147933139"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:D85CCD3DEBA9003CF3083B474976E281F056603C1CE55BC496F5ED88D068606A" wide //weight: 1
        $x_1_2 = {44 38 35 43 43 44 33 44 45 42 41 39 30 30 33 43 46 33 30 38 33 42 34 37 34 39 37 36 45 32 38 31 46 30 35 36 36 30 33 43 31 43 45 35 35 42 43 34 39 36 46 35 45 44 38 38 44 30 36 38 36 30 36 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {44 38 35 43 43 44 33 44 45 42 41 39 30 30 33 43 46 33 30 38 33 42 34 37 34 39 37 36 45 32 38 31 46 30 35 36 36 30 33 43 31 43 45 35 35 42 43 34 39 36 46 35 45 44 38 38 44 30 36 38 36 30 36 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\D85CCD3DEBA9003CF3083B474976E281F056603C1CE55BC496F5ED88D068606A.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_ID_2147933143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.ID"
        threat_id = "2147933143"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:3BBD6F23D4691C0C7613F9365E947A3CF7F0454CD792364E2A311EF80934C167" wide //weight: 1
        $x_1_2 = {33 42 42 44 36 46 32 33 44 34 36 39 31 43 30 43 37 36 31 33 46 39 33 36 35 45 39 34 37 41 33 43 46 37 46 30 34 35 34 43 44 37 39 32 33 36 34 45 32 41 33 31 31 45 46 38 30 39 33 34 43 31 36 37 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {33 42 42 44 36 46 32 33 44 34 36 39 31 43 30 43 37 36 31 33 46 39 33 36 35 45 39 34 37 41 33 43 46 37 46 30 34 35 34 43 44 37 39 32 33 36 34 45 32 41 33 31 31 45 46 38 30 39 33 34 43 31 36 37 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\3BBD6F23D4691C0C7613F9365E947A3CF7F0454CD792364E2A311EF80934C167.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_IE_2147933147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.IE"
        threat_id = "2147933147"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:3F7419E14A3039416E0A226F8D2EDF948A983298DF29A8E9A360CDD089414066" wide //weight: 1
        $x_1_2 = {33 46 37 34 31 39 45 31 34 41 33 30 33 39 34 31 36 45 30 41 32 32 36 46 38 44 32 45 44 46 39 34 38 41 39 38 33 32 39 38 44 46 32 39 41 38 45 39 41 33 36 30 43 44 44 30 38 39 34 31 34 30 36 36 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {33 46 37 34 31 39 45 31 34 41 33 30 33 39 34 31 36 45 30 41 32 32 36 46 38 44 32 45 44 46 39 34 38 41 39 38 33 32 39 38 44 46 32 39 41 38 45 39 41 33 36 30 43 44 44 30 38 39 34 31 34 30 36 36 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\3F7419E14A3039416E0A226F8D2EDF948A983298DF29A8E9A360CDD089414066.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_IF_2147933151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.IF"
        threat_id = "2147933151"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:46CA5EEC55A16767B7F8293DB18F753D1BF60C536747EFD115035DDA40948427" wide //weight: 1
        $x_1_2 = {34 36 43 41 35 45 45 43 35 35 41 31 36 37 36 37 42 37 46 38 32 39 33 44 42 31 38 46 37 35 33 44 31 42 46 36 30 43 35 33 36 37 34 37 45 46 44 31 31 35 30 33 35 44 44 41 34 30 39 34 38 34 32 37 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {34 36 43 41 35 45 45 43 35 35 41 31 36 37 36 37 42 37 46 38 32 39 33 44 42 31 38 46 37 35 33 44 31 42 46 36 30 43 35 33 36 37 34 37 45 46 44 31 31 35 30 33 35 44 44 41 34 30 39 34 38 34 32 37 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\46CA5EEC55A16767B7F8293DB18F753D1BF60C536747EFD115035DDA40948427.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_IG_2147933155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.IG"
        threat_id = "2147933155"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:620C7A54EC212FB482A684BA74381C3623CCE4D0E27FAE348688F65E0F0F6B6A" wide //weight: 1
        $x_1_2 = {36 32 30 43 37 41 35 34 45 43 32 31 32 46 42 34 38 32 41 36 38 34 42 41 37 34 33 38 31 43 33 36 32 33 43 43 45 34 44 30 45 32 37 46 41 45 33 34 38 36 38 38 46 36 35 45 30 46 30 46 36 42 36 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {36 32 30 43 37 41 35 34 45 43 32 31 32 46 42 34 38 32 41 36 38 34 42 41 37 34 33 38 31 43 33 36 32 33 43 43 45 34 44 30 45 32 37 46 41 45 33 34 38 36 38 38 46 36 35 45 30 46 30 46 36 42 36 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\620C7A54EC212FB482A684BA74381C3623CCE4D0E27FAE348688F65E0F0F6B6A.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_IH_2147933159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.IH"
        threat_id = "2147933159"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:74773DBD4085BA39A1643CFA561488124771BE839961793DA10245560E1F2D3A" wide //weight: 1
        $x_1_2 = {37 34 37 37 33 44 42 44 34 30 38 35 42 41 33 39 41 31 36 34 33 43 46 41 35 36 31 34 38 38 31 32 34 37 37 31 42 45 38 33 39 39 36 31 37 39 33 44 41 31 30 32 34 35 35 36 30 45 31 46 32 44 33 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {37 34 37 37 33 44 42 44 34 30 38 35 42 41 33 39 41 31 36 34 33 43 46 41 35 36 31 34 38 38 31 32 34 37 37 31 42 45 38 33 39 39 36 31 37 39 33 44 41 31 30 32 34 35 35 36 30 45 31 46 32 44 33 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\74773DBD4085BA39A1643CFA561488124771BE839961793DA10245560E1F2D3A.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_II_2147933163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.II"
        threat_id = "2147933163"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:90FDB446C1B8D204DE4EE3E393FD636C18798E744A34060C418EF96FD2C37C56" wide //weight: 1
        $x_1_2 = {39 30 46 44 42 34 34 36 43 31 42 38 44 32 30 34 44 45 34 45 45 33 45 33 39 33 46 44 36 33 36 43 31 38 37 39 38 45 37 34 34 41 33 34 30 36 30 43 34 31 38 45 46 39 36 46 44 32 43 33 37 43 35 36 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {39 30 46 44 42 34 34 36 43 31 42 38 44 32 30 34 44 45 34 45 45 33 45 33 39 33 46 44 36 33 36 43 31 38 37 39 38 45 37 34 34 41 33 34 30 36 30 43 34 31 38 45 46 39 36 46 44 32 43 33 37 43 35 36 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\90FDB446C1B8D204DE4EE3E393FD636C18798E744A34060C418EF96FD2C37C56.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_IJ_2147933167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.IJ"
        threat_id = "2147933167"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:B053968BBB63D64FE16CFC98AD114E9B2AB85DB5F2D6DA09D31B707868E01005" wide //weight: 1
        $x_1_2 = {42 30 35 33 39 36 38 42 42 42 36 33 44 36 34 46 45 31 36 43 46 43 39 38 41 44 31 31 34 45 39 42 32 41 42 38 35 44 42 35 46 32 44 36 44 41 30 39 44 33 31 42 37 30 37 38 36 38 45 30 31 30 30 35 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {42 30 35 33 39 36 38 42 42 42 36 33 44 36 34 46 45 31 36 43 46 43 39 38 41 44 31 31 34 45 39 42 32 41 42 38 35 44 42 35 46 32 44 36 44 41 30 39 44 33 31 42 37 30 37 38 36 38 45 30 31 30 30 35 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\B053968BBB63D64FE16CFC98AD114E9B2AB85DB5F2D6DA09D31B707868E01005.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_IK_2147933171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.IK"
        threat_id = "2147933171"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:BB3DEA31D39FAEF4E3286ED92DF5892E2A5966DAE28468A7BE8B72D54829A60F" wide //weight: 1
        $x_1_2 = {42 42 33 44 45 41 33 31 44 33 39 46 41 45 46 34 45 33 32 38 36 45 44 39 32 44 46 35 38 39 32 45 32 41 35 39 36 36 44 41 45 32 38 34 36 38 41 37 42 45 38 42 37 32 44 35 34 38 32 39 41 36 30 46 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {42 42 33 44 45 41 33 31 44 33 39 46 41 45 46 34 45 33 32 38 36 45 44 39 32 44 46 35 38 39 32 45 32 41 35 39 36 36 44 41 45 32 38 34 36 38 41 37 42 45 38 42 37 32 44 35 34 38 32 39 41 36 30 46 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\BB3DEA31D39FAEF4E3286ED92DF5892E2A5966DAE28468A7BE8B72D54829A60F.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_IL_2147933175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.IL"
        threat_id = "2147933175"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:C1DD64D0994AEAA297225CD94D1A6842819C74319A85350913AB9A82678C001E" wide //weight: 1
        $x_1_2 = {43 31 44 44 36 34 44 30 39 39 34 41 45 41 41 32 39 37 32 32 35 43 44 39 34 44 31 41 36 38 34 32 38 31 39 43 37 34 33 31 39 41 38 35 33 35 30 39 31 33 41 42 39 41 38 32 36 37 38 43 30 30 31 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {43 31 44 44 36 34 44 30 39 39 34 41 45 41 41 32 39 37 32 32 35 43 44 39 34 44 31 41 36 38 34 32 38 31 39 43 37 34 33 31 39 41 38 35 33 35 30 39 31 33 41 42 39 41 38 32 36 37 38 43 30 30 31 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\C1DD64D0994AEAA297225CD94D1A6842819C74319A85350913AB9A82678C001E.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_IM_2147933179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.IM"
        threat_id = "2147933179"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:E546611D2EFC92779973F7A270ACB77AD325A061B69F5D474608E8F9FFED2803" wide //weight: 1
        $x_1_2 = {45 35 34 36 36 31 31 44 32 45 46 43 39 32 37 37 39 39 37 33 46 37 41 32 37 30 41 43 42 37 37 41 44 33 32 35 41 30 36 31 42 36 39 46 35 44 34 37 34 36 30 38 45 38 46 39 46 46 45 44 32 38 30 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {45 35 34 36 36 31 31 44 32 45 46 43 39 32 37 37 39 39 37 33 46 37 41 32 37 30 41 43 42 37 37 41 44 33 32 35 41 30 36 31 42 36 39 46 35 44 34 37 34 36 30 38 45 38 46 39 46 46 45 44 32 38 30 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\E546611D2EFC92779973F7A270ACB77AD325A061B69F5D474608E8F9FFED2803.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_IN_2147933183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.IN"
        threat_id = "2147933183"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:EC6C1CE4914376904D32257187618E8CC0C5DA6CA98F96FB08E99A75672C1B44" wide //weight: 1
        $x_1_2 = {45 43 36 43 31 43 45 34 39 31 34 33 37 36 39 30 34 44 33 32 32 35 37 31 38 37 36 31 38 45 38 43 43 30 43 35 44 41 36 43 41 39 38 46 39 36 46 42 30 38 45 39 39 41 37 35 36 37 32 43 31 42 34 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {45 43 36 43 31 43 45 34 39 31 34 33 37 36 39 30 34 44 33 32 32 35 37 31 38 37 36 31 38 45 38 43 43 30 43 35 44 41 36 43 41 39 38 46 39 36 46 42 30 38 45 39 39 41 37 35 36 37 32 43 31 42 34 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\EC6C1CE4914376904D32257187618E8CC0C5DA6CA98F96FB08E99A75672C1B44.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_IO_2147933187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.IO"
        threat_id = "2147933187"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:F9342B8E15A0978EC2CEA5A9B9CD43F9110082256195A77F7031A2CEC8E8F871" wide //weight: 1
        $x_1_2 = {46 39 33 34 32 42 38 45 31 35 41 30 39 37 38 45 43 32 43 45 41 35 41 39 42 39 43 44 34 33 46 39 31 31 30 30 38 32 32 35 36 31 39 35 41 37 37 46 37 30 33 31 41 32 43 45 43 38 45 38 46 38 37 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {46 39 33 34 32 42 38 45 31 35 41 30 39 37 38 45 43 32 43 45 41 35 41 39 42 39 43 44 34 33 46 39 31 31 30 30 38 32 32 35 36 31 39 35 41 37 37 46 37 30 33 31 41 32 43 45 43 38 45 38 46 38 37 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\F9342B8E15A0978EC2CEA5A9B9CD43F9110082256195A77F7031A2CEC8E8F871.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_IP_2147933725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.IP"
        threat_id = "2147933725"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:24B03A9DA26336AF573D1DA2D67782C40975A64EFE2E118FE6209049E0F6E655" wide //weight: 1
        $x_1_2 = {32 34 42 30 33 41 39 44 41 32 36 33 33 36 41 46 35 37 33 44 31 44 41 32 44 36 37 37 38 32 43 34 30 39 37 35 41 36 34 45 46 45 32 45 31 31 38 46 45 36 32 30 39 30 34 39 45 30 46 36 45 36 35 35 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {32 34 42 30 33 41 39 44 41 32 36 33 33 36 41 46 35 37 33 44 31 44 41 32 44 36 37 37 38 32 43 34 30 39 37 35 41 36 34 45 46 45 32 45 31 31 38 46 45 36 32 30 39 30 34 39 45 30 46 36 45 36 35 35 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\24B03A9DA26336AF573D1DA2D67782C40975A64EFE2E118FE6209049E0F6E655.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_IQ_2147934242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.IQ"
        threat_id = "2147934242"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:EFE31926F41889DBF6588F27A2EC3A2D7DEF7D2E9E0A1DEFD39B976A49C11F0E" wide //weight: 1
        $x_1_2 = {45 46 45 33 31 39 32 36 46 34 31 38 38 39 44 42 46 36 35 38 38 46 32 37 41 32 45 43 33 41 32 44 37 44 45 46 37 44 32 45 39 45 30 41 31 44 45 46 44 33 39 42 39 37 36 41 34 39 43 31 31 46 30 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {45 46 45 33 31 39 32 36 46 34 31 38 38 39 44 42 46 36 35 38 38 46 32 37 41 32 45 43 33 41 32 44 37 44 45 46 37 44 32 45 39 45 30 41 31 44 45 46 44 33 39 42 39 37 36 41 34 39 43 31 31 46 30 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\EFE31926F41889DBF6588F27A2EC3A2D7DEF7D2E9E0A1DEFD39B976A49C11F0E.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_IR_2147934246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.IR"
        threat_id = "2147934246"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:E83CD54EAAB0F31040D855E1ED993E2AC92652FF8E8742D3901580339D135C6E" wide //weight: 1
        $x_1_2 = {45 38 33 43 44 35 34 45 41 41 42 30 46 33 31 30 34 30 44 38 35 35 45 31 45 44 39 39 33 45 32 41 43 39 32 36 35 32 46 46 38 45 38 37 34 32 44 33 39 30 31 35 38 30 33 33 39 44 31 33 35 43 36 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {45 38 33 43 44 35 34 45 41 41 42 30 46 33 31 30 34 30 44 38 35 35 45 31 45 44 39 39 33 45 32 41 43 39 32 36 35 32 46 46 38 45 38 37 34 32 44 33 39 30 31 35 38 30 33 33 39 44 31 33 35 43 36 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\E83CD54EAAB0F31040D855E1ED993E2AC92652FF8E8742D3901580339D135C6E.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_IS_2147934366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.IS"
        threat_id = "2147934366"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:9453686EAB63923D1C35C92DDE5E61A6534DD067B5448C1C8D996A460B92CA50" wide //weight: 1
        $x_1_2 = {39 34 35 33 36 38 36 45 41 42 36 33 39 32 33 44 31 43 33 35 43 39 32 44 44 45 35 45 36 31 41 36 35 33 34 44 44 30 36 37 42 35 34 34 38 43 31 43 38 44 39 39 36 41 34 36 30 42 39 32 43 41 35 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {39 34 35 33 36 38 36 45 41 42 36 33 39 32 33 44 31 43 33 35 43 39 32 44 44 45 35 45 36 31 41 36 35 33 34 44 44 30 36 37 42 35 34 34 38 43 31 43 38 44 39 39 36 41 34 36 30 42 39 32 43 41 35 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\9453686EAB63923D1C35C92DDE5E61A6534DD067B5448C1C8D996A460B92CA50.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_IT_2147935784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.IT"
        threat_id = "2147935784"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:FEE914521FB507AB978107ACE3B69B4CA41DA89859408BAE23E1512E8C2E614A" wide //weight: 1
        $x_1_2 = {46 45 45 39 31 34 35 32 31 46 42 35 30 37 41 42 39 37 38 31 30 37 41 43 45 33 42 36 39 42 34 43 41 34 31 44 41 38 39 38 35 39 34 30 38 42 41 45 32 33 45 31 35 31 32 45 38 43 32 45 36 31 34 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {46 45 45 39 31 34 35 32 31 46 42 35 30 37 41 42 39 37 38 31 30 37 41 43 45 33 42 36 39 42 34 43 41 34 31 44 41 38 39 38 35 39 34 30 38 42 41 45 32 33 45 31 35 31 32 45 38 43 32 45 36 31 34 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\FEE914521FB507AB978107ACE3B69B4CA41DA89859408BAE23E1512E8C2E614A.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_IU_2147935788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.IU"
        threat_id = "2147935788"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:570D7C5DE6B5CDB2D2E9D866C7511301E5566D988B7FA341F30CC3B81A29AE40" wide //weight: 1
        $x_1_2 = {35 37 30 44 37 43 35 44 45 36 42 35 43 44 42 32 44 32 45 39 44 38 36 36 43 37 35 31 31 33 30 31 45 35 35 36 36 44 39 38 38 42 37 46 41 33 34 31 46 33 30 43 43 33 42 38 31 41 32 39 41 45 34 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {35 37 30 44 37 43 35 44 45 36 42 35 43 44 42 32 44 32 45 39 44 38 36 36 43 37 35 31 31 33 30 31 45 35 35 36 36 44 39 38 38 42 37 46 41 33 34 31 46 33 30 43 43 33 42 38 31 41 32 39 41 45 34 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\570D7C5DE6B5CDB2D2E9D866C7511301E5566D988B7FA341F30CC3B81A29AE40.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_IV_2147937408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.IV"
        threat_id = "2147937408"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:0995EB69C04148B6DFBC4775B090834F6E05C36944C6770625984A9A2A2FC23B" wide //weight: 1
        $x_1_2 = {30 39 39 35 45 42 36 39 43 30 34 31 34 38 42 36 44 46 42 43 34 37 37 35 42 30 39 30 38 33 34 46 36 45 30 35 43 33 36 39 34 34 43 36 37 37 30 36 32 35 39 38 34 41 39 41 32 41 32 46 43 32 33 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {30 39 39 35 45 42 36 39 43 30 34 31 34 38 42 36 44 46 42 43 34 37 37 35 42 30 39 30 38 33 34 46 36 45 30 35 43 33 36 39 34 34 43 36 37 37 30 36 32 35 39 38 34 41 39 41 32 41 32 46 43 32 33 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\0995EB69C04148B6DFBC4775B090834F6E05C36944C6770625984A9A2A2FC23B.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_IW_2147937412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.IW"
        threat_id = "2147937412"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:11D0F394AB8F6F0ECD1321A3743A22D7FC149DB03B505C29B2E541BCC480AF37" wide //weight: 1
        $x_1_2 = {31 31 44 30 46 33 39 34 41 42 38 46 36 46 30 45 43 44 31 33 32 31 41 33 37 34 33 41 32 32 44 37 46 43 31 34 39 44 42 30 33 42 35 30 35 43 32 39 42 32 45 35 34 31 42 43 43 34 38 30 41 46 33 37 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {31 31 44 30 46 33 39 34 41 42 38 46 36 46 30 45 43 44 31 33 32 31 41 33 37 34 33 41 32 32 44 37 46 43 31 34 39 44 42 30 33 42 35 30 35 43 32 39 42 32 45 35 34 31 42 43 43 34 38 30 41 46 33 37 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\11D0F394AB8F6F0ECD1321A3743A22D7FC149DB03B505C29B2E541BCC480AF37.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_IX_2147937416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.IX"
        threat_id = "2147937416"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:179ECED0DCE8C07CDFBEA3F290B80B3B6F8BE1500A773F45396CF39183EB5845" wide //weight: 1
        $x_1_2 = {31 37 39 45 43 45 44 30 44 43 45 38 43 30 37 43 44 46 42 45 41 33 46 32 39 30 42 38 30 42 33 42 36 46 38 42 45 31 35 30 30 41 37 37 33 46 34 35 33 39 36 43 46 33 39 31 38 33 45 42 35 38 34 35 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {31 37 39 45 43 45 44 30 44 43 45 38 43 30 37 43 44 46 42 45 41 33 46 32 39 30 42 38 30 42 33 42 36 46 38 42 45 31 35 30 30 41 37 37 33 46 34 35 33 39 36 43 46 33 39 31 38 33 45 42 35 38 34 35 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\179ECED0DCE8C07CDFBEA3F290B80B3B6F8BE1500A773F45396CF39183EB5845.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_IY_2147937420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.IY"
        threat_id = "2147937420"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:1EE7194E5F5699163B8B875F272B780FB72FE49C0F21705BF0335698853CC35A" wide //weight: 1
        $x_1_2 = {31 45 45 37 31 39 34 45 35 46 35 36 39 39 31 36 33 42 38 42 38 37 35 46 32 37 32 42 37 38 30 46 42 37 32 46 45 34 39 43 30 46 32 31 37 30 35 42 46 30 33 33 35 36 39 38 38 35 33 43 43 33 35 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {31 45 45 37 31 39 34 45 35 46 35 36 39 39 31 36 33 42 38 42 38 37 35 46 32 37 32 42 37 38 30 46 42 37 32 46 45 34 39 43 30 46 32 31 37 30 35 42 46 30 33 33 35 36 39 38 38 35 33 43 43 33 35 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\1EE7194E5F5699163B8B875F272B780FB72FE49C0F21705BF0335698853CC35A.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_IZ_2147937424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.IZ"
        threat_id = "2147937424"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:349426AEB4CD3338C9A1AAE88D2F61EA53F0D9E9EB547060D66777CB84CB2702" wide //weight: 1
        $x_1_2 = {33 34 39 34 32 36 41 45 42 34 43 44 33 33 33 38 43 39 41 31 41 41 45 38 38 44 32 46 36 31 45 41 35 33 46 30 44 39 45 39 45 42 35 34 37 30 36 30 44 36 36 37 37 37 43 42 38 34 43 42 32 37 30 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {33 34 39 34 32 36 41 45 42 34 43 44 33 33 33 38 43 39 41 31 41 41 45 38 38 44 32 46 36 31 45 41 35 33 46 30 44 39 45 39 45 42 35 34 37 30 36 30 44 36 36 37 37 37 43 42 38 34 43 42 32 37 30 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\349426AEB4CD3338C9A1AAE88D2F61EA53F0D9E9EB547060D66777CB84CB2702.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_JA_2147937428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.JA"
        threat_id = "2147937428"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:48FC6C22548154CC2C19495A56A69E7FBDB8D3C13EBF4D526BD49746B72E1B4D" wide //weight: 1
        $x_1_2 = {34 38 46 43 36 43 32 32 35 34 38 31 35 34 43 43 32 43 31 39 34 39 35 41 35 36 41 36 39 45 37 46 42 44 42 38 44 33 43 31 33 45 42 46 34 44 35 32 36 42 44 34 39 37 34 36 42 37 32 45 31 42 34 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {34 38 46 43 36 43 32 32 35 34 38 31 35 34 43 43 32 43 31 39 34 39 35 41 35 36 41 36 39 45 37 46 42 44 42 38 44 33 43 31 33 45 42 46 34 44 35 32 36 42 44 34 39 37 34 36 42 37 32 45 31 42 34 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\48FC6C22548154CC2C19495A56A69E7FBDB8D3C13EBF4D526BD49746B72E1B4D.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_JB_2147937432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.JB"
        threat_id = "2147937432"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:4BA82D3C2DEEC79996BF9B06BD91B5C98BB11F6D3B1E269668B2FAC1F538BA65" wide //weight: 1
        $x_1_2 = {34 42 41 38 32 44 33 43 32 44 45 45 43 37 39 39 39 36 42 46 39 42 30 36 42 44 39 31 42 35 43 39 38 42 42 31 31 46 36 44 33 42 31 45 32 36 39 36 36 38 42 32 46 41 43 31 46 35 33 38 42 41 36 35 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {34 42 41 38 32 44 33 43 32 44 45 45 43 37 39 39 39 36 42 46 39 42 30 36 42 44 39 31 42 35 43 39 38 42 42 31 31 46 36 44 33 42 31 45 32 36 39 36 36 38 42 32 46 41 43 31 46 35 33 38 42 41 36 35 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\4BA82D3C2DEEC79996BF9B06BD91B5C98BB11F6D3B1E269668B2FAC1F538BA65.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_JC_2147937436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.JC"
        threat_id = "2147937436"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:7D514FF4BADC574BE0C71DD2D01370F3377CBE820BBDE79A6F0A0D46C4F8D75C" wide //weight: 1
        $x_1_2 = {37 44 35 31 34 46 46 34 42 41 44 43 35 37 34 42 45 30 43 37 31 44 44 32 44 30 31 33 37 30 46 33 33 37 37 43 42 45 38 32 30 42 42 44 45 37 39 41 36 46 30 41 30 44 34 36 43 34 46 38 44 37 35 43 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {37 44 35 31 34 46 46 34 42 41 44 43 35 37 34 42 45 30 43 37 31 44 44 32 44 30 31 33 37 30 46 33 33 37 37 43 42 45 38 32 30 42 42 44 45 37 39 41 36 46 30 41 30 44 34 36 43 34 46 38 44 37 35 43 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\7D514FF4BADC574BE0C71DD2D01370F3377CBE820BBDE79A6F0A0D46C4F8D75C.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_JD_2147937440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.JD"
        threat_id = "2147937440"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:7DA3575AC5D57B3B5B93914DEF1E87AAD80319C2F5779F68B53A329AD7C1DE45" wide //weight: 1
        $x_1_2 = {37 44 41 33 35 37 35 41 43 35 44 35 37 42 33 42 35 42 39 33 39 31 34 44 45 46 31 45 38 37 41 41 44 38 30 33 31 39 43 32 46 35 37 37 39 46 36 38 42 35 33 41 33 32 39 41 44 37 43 31 44 45 34 35 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {37 44 41 33 35 37 35 41 43 35 44 35 37 42 33 42 35 42 39 33 39 31 34 44 45 46 31 45 38 37 41 41 44 38 30 33 31 39 43 32 46 35 37 37 39 46 36 38 42 35 33 41 33 32 39 41 44 37 43 31 44 45 34 35 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\7DA3575AC5D57B3B5B93914DEF1E87AAD80319C2F5779F68B53A329AD7C1DE45.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_JE_2147937444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.JE"
        threat_id = "2147937444"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:A990C13C53C7C926595A144AC3C3919C64CF2CBE300F77EA969383ED785BCD22" wide //weight: 1
        $x_1_2 = {41 39 39 30 43 31 33 43 35 33 43 37 43 39 32 36 35 39 35 41 31 34 34 41 43 33 43 33 39 31 39 43 36 34 43 46 32 43 42 45 33 30 30 46 37 37 45 41 39 36 39 33 38 33 45 44 37 38 35 42 43 44 32 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {41 39 39 30 43 31 33 43 35 33 43 37 43 39 32 36 35 39 35 41 31 34 34 41 43 33 43 33 39 31 39 43 36 34 43 46 32 43 42 45 33 30 30 46 37 37 45 41 39 36 39 33 38 33 45 44 37 38 35 42 43 44 32 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\A990C13C53C7C926595A144AC3C3919C64CF2CBE300F77EA969383ED785BCD22.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_JF_2147937448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.JF"
        threat_id = "2147937448"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:CE1604BCC1D5B7543AFAB646518363E926F33EA97F5DA5C77CDAF38633A25E43" wide //weight: 1
        $x_1_2 = {43 45 31 36 30 34 42 43 43 31 44 35 42 37 35 34 33 41 46 41 42 36 34 36 35 31 38 33 36 33 45 39 32 36 46 33 33 45 41 39 37 46 35 44 41 35 43 37 37 43 44 41 46 33 38 36 33 33 41 32 35 45 34 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {43 45 31 36 30 34 42 43 43 31 44 35 42 37 35 34 33 41 46 41 42 36 34 36 35 31 38 33 36 33 45 39 32 36 46 33 33 45 41 39 37 46 35 44 41 35 43 37 37 43 44 41 46 33 38 36 33 33 41 32 35 45 34 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\CE1604BCC1D5B7543AFAB646518363E926F33EA97F5DA5C77CDAF38633A25E43.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_JG_2147937452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.JG"
        threat_id = "2147937452"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:CF62DD142C7FBC8E79ECB16973DA572E918D6A8D69B4E163A91EFF91A0D0674B" wide //weight: 1
        $x_1_2 = {43 46 36 32 44 44 31 34 32 43 37 46 42 43 38 45 37 39 45 43 42 31 36 39 37 33 44 41 35 37 32 45 39 31 38 44 36 41 38 44 36 39 42 34 45 31 36 33 41 39 31 45 46 46 39 31 41 30 44 30 36 37 34 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {43 46 36 32 44 44 31 34 32 43 37 46 42 43 38 45 37 39 45 43 42 31 36 39 37 33 44 41 35 37 32 45 39 31 38 44 36 41 38 44 36 39 42 34 45 31 36 33 41 39 31 45 46 46 39 31 41 30 44 30 36 37 34 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\CF62DD142C7FBC8E79ECB16973DA572E918D6A8D69B4E163A91EFF91A0D0674B.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_JH_2147937456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.JH"
        threat_id = "2147937456"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:D2CA90BD5028C4DDE223E20674062AD45C6629D666FBFC9C4ECDCE2493700069" wide //weight: 1
        $x_1_2 = {44 32 43 41 39 30 42 44 35 30 32 38 43 34 44 44 45 32 32 33 45 32 30 36 37 34 30 36 32 41 44 34 35 43 36 36 32 39 44 36 36 36 46 42 46 43 39 43 34 45 43 44 43 45 32 34 39 33 37 30 30 30 36 39 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {44 32 43 41 39 30 42 44 35 30 32 38 43 34 44 44 45 32 32 33 45 32 30 36 37 34 30 36 32 41 44 34 35 43 36 36 32 39 44 36 36 36 46 42 46 43 39 43 34 45 43 44 43 45 32 34 39 33 37 30 30 30 36 39 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\D2CA90BD5028C4DDE223E20674062AD45C6629D666FBFC9C4ECDCE2493700069.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_JI_2147937460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.JI"
        threat_id = "2147937460"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:F7FACEB9D3F06F8A45896C03A7D88B5D3090CEE38D3EF908BCDE83BC65E2CA30" wide //weight: 1
        $x_1_2 = {46 37 46 41 43 45 42 39 44 33 46 30 36 46 38 41 34 35 38 39 36 43 30 33 41 37 44 38 38 42 35 44 33 30 39 30 43 45 45 33 38 44 33 45 46 39 30 38 42 43 44 45 38 33 42 43 36 35 45 32 43 41 33 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {46 37 46 41 43 45 42 39 44 33 46 30 36 46 38 41 34 35 38 39 36 43 30 33 41 37 44 38 38 42 35 44 33 30 39 30 43 45 45 33 38 44 33 45 46 39 30 38 42 43 44 45 38 33 42 43 36 35 45 32 43 41 33 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\F7FACEB9D3F06F8A45896C03A7D88B5D3090CEE38D3EF908BCDE83BC65E2CA30.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_JJ_2147937464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.JJ"
        threat_id = "2147937464"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:FB9B2B31E76E2672AE7F14F3F394B3064529B5762B329F602C422D0D75009E6A" wide //weight: 1
        $x_1_2 = {46 42 39 42 32 42 33 31 45 37 36 45 32 36 37 32 41 45 37 46 31 34 46 33 46 33 39 34 42 33 30 36 34 35 32 39 42 35 37 36 32 42 33 32 39 46 36 30 32 43 34 32 32 44 30 44 37 35 30 30 39 45 36 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {46 42 39 42 32 42 33 31 45 37 36 45 32 36 37 32 41 45 37 46 31 34 46 33 46 33 39 34 42 33 30 36 34 35 32 39 42 35 37 36 32 42 33 32 39 46 36 30 32 43 34 32 32 44 30 44 37 35 30 30 39 45 36 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\FB9B2B31E76E2672AE7F14F3F394B3064529B5762B329F602C422D0D75009E6A.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_JK_2147937468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.JK"
        threat_id = "2147937468"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:FD38D64D730DFD46889E569AE6BB2681431692BD7FB038EFECA7E8B044CF511E" wide //weight: 1
        $x_1_2 = {46 44 33 38 44 36 34 44 37 33 30 44 46 44 34 36 38 38 39 45 35 36 39 41 45 36 42 42 32 36 38 31 34 33 31 36 39 32 42 44 37 46 42 30 33 38 45 46 45 43 41 37 45 38 42 30 34 34 43 46 35 31 31 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {46 44 33 38 44 36 34 44 37 33 30 44 46 44 34 36 38 38 39 45 35 36 39 41 45 36 42 42 32 36 38 31 34 33 31 36 39 32 42 44 37 46 42 30 33 38 45 46 45 43 41 37 45 38 42 30 34 34 43 46 35 31 31 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\FD38D64D730DFD46889E569AE6BB2681431692BD7FB038EFECA7E8B044CF511E.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_JL_2147939913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.JL"
        threat_id = "2147939913"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:0C8E5B45C57AE244E9C904C5BC74F73306937469D9CEA22541CA69AC162B8D42" wide //weight: 1
        $x_1_2 = {30 43 38 45 35 42 34 35 43 35 37 41 45 32 34 34 45 39 43 39 30 34 43 35 42 43 37 34 46 37 33 33 30 36 39 33 37 34 36 39 44 39 43 45 41 32 32 35 34 31 43 41 36 39 41 43 31 36 32 42 38 44 34 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {30 43 38 45 35 42 34 35 43 35 37 41 45 32 34 34 45 39 43 39 30 34 43 35 42 43 37 34 46 37 33 33 30 36 39 33 37 34 36 39 44 39 43 45 41 32 32 35 34 31 43 41 36 39 41 43 31 36 32 42 38 44 34 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\0C8E5B45C57AE244E9C904C5BC74F73306937469D9CEA22541CA69AC162B8D42.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_JM_2147940257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.JM"
        threat_id = "2147940257"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:E8481B6E149862EEEA79668EBBC50B96A6B6529C5DDD905491E2F838EF7D174F" wide //weight: 1
        $x_1_2 = {45 38 34 38 31 42 36 45 31 34 39 38 36 32 45 45 45 41 37 39 36 36 38 45 42 42 43 35 30 42 39 36 41 36 42 36 35 32 39 43 35 44 44 44 39 30 35 34 39 31 45 32 46 38 33 38 45 46 37 44 31 37 34 46 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {45 38 34 38 31 42 36 45 31 34 39 38 36 32 45 45 45 41 37 39 36 36 38 45 42 42 43 35 30 42 39 36 41 36 42 36 35 32 39 43 35 44 44 44 39 30 35 34 39 31 45 32 46 38 33 38 45 46 37 44 31 37 34 46 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\E8481B6E149862EEEA79668EBBC50B96A6B6529C5DDD905491E2F838EF7D174F.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_JN_2147942770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.JN"
        threat_id = "2147942770"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:9D97F166730F865F793E2EA07B173C742A6302879DE1B0BBB03817A5A04B572F" wide //weight: 1
        $x_1_2 = {39 44 39 37 46 31 36 36 37 33 30 46 38 36 35 46 37 39 33 45 32 45 41 30 37 42 31 37 33 43 37 34 32 41 36 33 30 32 38 37 39 44 45 31 42 30 42 42 42 30 33 38 31 37 41 35 41 30 34 42 35 37 32 46 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {39 44 39 37 46 31 36 36 37 33 30 46 38 36 35 46 37 39 33 45 32 45 41 30 37 42 31 37 33 43 37 34 32 41 36 33 30 32 38 37 39 44 45 31 42 30 42 42 42 30 33 38 31 37 41 35 41 30 34 42 35 37 32 46 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\9D97F166730F865F793E2EA07B173C742A6302879DE1B0BBB03817A5A04B572F.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_JO_2147942965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.JO"
        threat_id = "2147942965"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:BBF77F0461AEE151529EC77FBFD38D5818AAED1DC6A9E6AD65D96717453B7921" wide //weight: 1
        $x_1_2 = {42 42 46 37 37 46 30 34 36 31 41 45 45 31 35 31 35 32 39 45 43 37 37 46 42 46 44 33 38 44 35 38 31 38 41 41 45 44 31 44 43 36 41 39 45 36 41 44 36 35 44 39 36 37 31 37 34 35 33 42 37 39 32 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {42 42 46 37 37 46 30 34 36 31 41 45 45 31 35 31 35 32 39 45 43 37 37 46 42 46 44 33 38 44 35 38 31 38 41 41 45 44 31 44 43 36 41 39 45 36 41 44 36 35 44 39 36 37 31 37 34 35 33 42 37 39 32 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\BBF77F0461AEE151529EC77FBFD38D5818AAED1DC6A9E6AD65D96717453B7921.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_JP_2147942969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.JP"
        threat_id = "2147942969"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:644D8416E1695DC98593DFB5E55CF50F209327665D28655164511E2482D0F80B" wide //weight: 1
        $x_1_2 = {36 34 34 44 38 34 31 36 45 31 36 39 35 44 43 39 38 35 39 33 44 46 42 35 45 35 35 43 46 35 30 46 32 30 39 33 32 37 36 36 35 44 32 38 36 35 35 31 36 34 35 31 31 45 32 34 38 32 44 30 46 38 30 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {36 34 34 44 38 34 31 36 45 31 36 39 35 44 43 39 38 35 39 33 44 46 42 35 45 35 35 43 46 35 30 46 32 30 39 33 32 37 36 36 35 44 32 38 36 35 35 31 36 34 35 31 31 45 32 34 38 32 44 30 46 38 30 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\644D8416E1695DC98593DFB5E55CF50F209327665D28655164511E2482D0F80B.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_JQ_2147942973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.JQ"
        threat_id = "2147942973"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:AF9C4725A434490923A9F4C32B5F9003ED77428AD82AF86E757120F743A96D28" wide //weight: 1
        $x_1_2 = {41 46 39 43 34 37 32 35 41 34 33 34 34 39 30 39 32 33 41 39 46 34 43 33 32 42 35 46 39 30 30 33 45 44 37 37 34 32 38 41 44 38 32 41 46 38 36 45 37 35 37 31 32 30 46 37 34 33 41 39 36 44 32 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {41 46 39 43 34 37 32 35 41 34 33 34 34 39 30 39 32 33 41 39 46 34 43 33 32 42 35 46 39 30 30 33 45 44 37 37 34 32 38 41 44 38 32 41 46 38 36 45 37 35 37 31 32 30 46 37 34 33 41 39 36 44 32 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\AF9C4725A434490923A9F4C32B5F9003ED77428AD82AF86E757120F743A96D28.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_JR_2147944074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.JR"
        threat_id = "2147944074"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:DC9D709BD034A7CC6BE02E58E1159B724FB4A75BBDD47D53CFF86724A60BB223" wide //weight: 1
        $x_1_2 = {44 43 39 44 37 30 39 42 44 30 33 34 41 37 43 43 36 42 45 30 32 45 35 38 45 31 31 35 39 42 37 32 34 46 42 34 41 37 35 42 42 44 44 34 37 44 35 33 43 46 46 38 36 37 32 34 41 36 30 42 42 32 32 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {44 43 39 44 37 30 39 42 44 30 33 34 41 37 43 43 36 42 45 30 32 45 35 38 45 31 31 35 39 42 37 32 34 46 42 34 41 37 35 42 42 44 44 34 37 44 35 33 43 46 46 38 36 37 32 34 41 36 30 42 42 32 32 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\DC9D709BD034A7CC6BE02E58E1159B724FB4A75BBDD47D53CFF86724A60BB223.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_JS_2147944571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.JS"
        threat_id = "2147944571"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:457BB4E5DF0E650509322CA894758D925A568828090A3449D5AEEED30E9B8E18" wide //weight: 1
        $x_1_2 = {34 35 37 42 42 34 45 35 44 46 30 45 36 35 30 35 30 39 33 32 32 43 41 38 39 34 37 35 38 44 39 32 35 41 35 36 38 38 32 38 30 39 30 41 33 34 34 39 44 35 41 45 45 45 44 33 30 45 39 42 38 45 31 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {34 35 37 42 42 34 45 35 44 46 30 45 36 35 30 35 30 39 33 32 32 43 41 38 39 34 37 35 38 44 39 32 35 41 35 36 38 38 32 38 30 39 30 41 33 34 34 39 44 35 41 45 45 45 44 33 30 45 39 42 38 45 31 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\457BB4E5DF0E650509322CA894758D925A568828090A3449D5AEEED30E9B8E18.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_JT_2147945162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.JT"
        threat_id = "2147945162"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:AFD02E37CDA7D994F7E91FE7ACE71DE2E88F5C49233D3EFAB3210554629A6E5E" wide //weight: 1
        $x_1_2 = {41 46 44 30 32 45 33 37 43 44 41 37 44 39 39 34 46 37 45 39 31 46 45 37 41 43 45 37 31 44 45 32 45 38 38 46 35 43 34 39 32 33 33 44 33 45 46 41 42 33 32 31 30 35 35 34 36 32 39 41 36 45 35 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {41 46 44 30 32 45 33 37 43 44 41 37 44 39 39 34 46 37 45 39 31 46 45 37 41 43 45 37 31 44 45 32 45 38 38 46 35 43 34 39 32 33 33 44 33 45 46 41 42 33 32 31 30 35 35 34 36 32 39 41 36 45 35 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\AFD02E37CDA7D994F7E91FE7ACE71DE2E88F5C49233D3EFAB3210554629A6E5E.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_JU_2147945799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.JU"
        threat_id = "2147945799"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:BFC836EBAE06450FDD36B63170F121F44ADADFF2DAFAAFA41314B6778F600350" wide //weight: 1
        $x_1_2 = {42 46 43 38 33 36 45 42 41 45 30 36 34 35 30 46 44 44 33 36 42 36 33 31 37 30 46 31 32 31 46 34 34 41 44 41 44 46 46 32 44 41 46 41 41 46 41 34 31 33 31 34 42 36 37 37 38 46 36 30 30 33 35 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {42 46 43 38 33 36 45 42 41 45 30 36 34 35 30 46 44 44 33 36 42 36 33 31 37 30 46 31 32 31 46 34 34 41 44 41 44 46 46 32 44 41 46 41 41 46 41 34 31 33 31 34 42 36 37 37 38 46 36 30 30 33 35 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\BFC836EBAE06450FDD36B63170F121F44ADADFF2DAFAAFA41314B6778F600350.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_JV_2147945803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.JV"
        threat_id = "2147945803"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:EC99BD5A36DE69144F5402C832B5413295323FC7C12259C53E4AA6D5BC2D4E6D" wide //weight: 1
        $x_1_2 = {45 43 39 39 42 44 35 41 33 36 44 45 36 39 31 34 34 46 35 34 30 32 43 38 33 32 42 35 34 31 33 32 39 35 33 32 33 46 43 37 43 31 32 32 35 39 43 35 33 45 34 41 41 36 44 35 42 43 32 44 34 45 36 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {45 43 39 39 42 44 35 41 33 36 44 45 36 39 31 34 34 46 35 34 30 32 43 38 33 32 42 35 34 31 33 32 39 35 33 32 33 46 43 37 43 31 32 32 35 39 43 35 33 45 34 41 41 36 44 35 42 43 32 44 34 45 36 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\EC99BD5A36DE69144F5402C832B5413295323FC7C12259C53E4AA6D5BC2D4E6D.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_JW_2147946173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.JW"
        threat_id = "2147946173"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:50FA856FE57D6A299A738A0D1E19E69EAF2C5409D617919580242BACAFC88A1D" wide //weight: 1
        $x_1_2 = {35 30 46 41 38 35 36 46 45 35 37 44 36 41 32 39 39 41 37 33 38 41 30 44 31 45 31 39 45 36 39 45 41 46 32 43 35 34 30 39 44 36 31 37 39 31 39 35 38 30 32 34 32 42 41 43 41 46 43 38 38 41 31 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {35 30 46 41 38 35 36 46 45 35 37 44 36 41 32 39 39 41 37 33 38 41 30 44 31 45 31 39 45 36 39 45 41 46 32 43 35 34 30 39 44 36 31 37 39 31 39 35 38 30 32 34 32 42 41 43 41 46 43 38 38 41 31 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\50FA856FE57D6A299A738A0D1E19E69EAF2C5409D617919580242BACAFC88A1D.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_JX_2147946255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.JX"
        threat_id = "2147946255"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:6A340207246B47E37F6D094D2236E5C6242B6E4461EEF8021FED2C9855240C3E" wide //weight: 1
        $x_1_2 = {36 41 33 34 30 32 30 37 32 34 36 42 34 37 45 33 37 46 36 44 30 39 34 44 32 32 33 36 45 35 43 36 32 34 32 42 36 45 34 34 36 31 45 45 46 38 30 32 31 46 45 44 32 43 39 38 35 35 32 34 30 43 33 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {36 41 33 34 30 32 30 37 32 34 36 42 34 37 45 33 37 46 36 44 30 39 34 44 32 32 33 36 45 35 43 36 32 34 32 42 36 45 34 34 36 31 45 45 46 38 30 32 31 46 45 44 32 43 39 38 35 35 32 34 30 43 33 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\6A340207246B47E37F6D094D2236E5C6242B6E4461EEF8021FED2C9855240C3E.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_JY_2147946441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.JY"
        threat_id = "2147946441"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:535F403A2EA2DC71A392E18D7DB77FEF70845C0B7E5B9114CD30D30187030437" wide //weight: 1
        $x_1_2 = {35 33 35 46 34 30 33 41 32 45 41 32 44 43 37 31 41 33 39 32 45 31 38 44 37 44 42 37 37 46 45 46 37 30 38 34 35 43 30 42 37 45 35 42 39 31 31 34 43 44 33 30 44 33 30 31 38 37 30 33 30 34 33 37 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {35 33 35 46 34 30 33 41 32 45 41 32 44 43 37 31 41 33 39 32 45 31 38 44 37 44 42 37 37 46 45 46 37 30 38 34 35 43 30 42 37 45 35 42 39 31 31 34 43 44 33 30 44 33 30 31 38 37 30 33 30 34 33 37 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\535F403A2EA2DC71A392E18D7DB77FEF70845C0B7E5B9114CD30D30187030437.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_JZ_2147946501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.JZ"
        threat_id = "2147946501"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:B26253E0A8F87CBBA29519E7295397631326D94162D29F9A2B1CAE6899791210" wide //weight: 1
        $x_1_2 = {42 32 36 32 35 33 45 30 41 38 46 38 37 43 42 42 41 32 39 35 31 39 45 37 32 39 35 33 39 37 36 33 31 33 32 36 44 39 34 31 36 32 44 32 39 46 39 41 32 42 31 43 41 45 36 38 39 39 37 39 31 32 31 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {42 32 36 32 35 33 45 30 41 38 46 38 37 43 42 42 41 32 39 35 31 39 45 37 32 39 35 33 39 37 36 33 31 33 32 36 44 39 34 31 36 32 44 32 39 46 39 41 32 42 31 43 41 45 36 38 39 39 37 39 31 32 31 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\B26253E0A8F87CBBA29519E7295397631326D94162D29F9A2B1CAE6899791210.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_KA_2147946505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.KA"
        threat_id = "2147946505"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:23B35DB9AC6DEFD7F2EF445F3F8B1DB1B046756605110AC7C73AF90ED7952B5A" wide //weight: 1
        $x_1_2 = {32 33 42 33 35 44 42 39 41 43 36 44 45 46 44 37 46 32 45 46 34 34 35 46 33 46 38 42 31 44 42 31 42 30 34 36 37 35 36 36 30 35 31 31 30 41 43 37 43 37 33 41 46 39 30 45 44 37 39 35 32 42 35 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {32 33 42 33 35 44 42 39 41 43 36 44 45 46 44 37 46 32 45 46 34 34 35 46 33 46 38 42 31 44 42 31 42 30 34 36 37 35 36 36 30 35 31 31 30 41 43 37 43 37 33 41 46 39 30 45 44 37 39 35 32 42 35 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\23B35DB9AC6DEFD7F2EF445F3F8B1DB1B046756605110AC7C73AF90ED7952B5A.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_KB_2147946879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.KB"
        threat_id = "2147946879"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:6A1448416828F6D1F3BA7814E7F7E7D7C0A3C21FE7447F547430513F2E0A0441" wide //weight: 1
        $x_1_2 = {36 41 31 34 34 38 34 31 36 38 32 38 46 36 44 31 46 33 42 41 37 38 31 34 45 37 46 37 45 37 44 37 43 30 41 33 43 32 31 46 45 37 34 34 37 46 35 34 37 34 33 30 35 31 33 46 32 45 30 41 30 34 34 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {36 41 31 34 34 38 34 31 36 38 32 38 46 36 44 31 46 33 42 41 37 38 31 34 45 37 46 37 45 37 44 37 43 30 41 33 43 32 31 46 45 37 34 34 37 46 35 34 37 34 33 30 35 31 33 46 32 45 30 41 30 34 34 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\6A1448416828F6D1F3BA7814E7F7E7D7C0A3C21FE7447F547430513F2E0A0441.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_KC_2147947216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.KC"
        threat_id = "2147947216"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:3DCE1C43491FC92EA7010322040B254FDD2731001C2DDC2B9E819F0C946BDC3C" wide //weight: 1
        $x_1_2 = {33 44 43 45 31 43 34 33 34 39 31 46 43 39 32 45 41 37 30 31 30 33 32 32 30 34 30 42 32 35 34 46 44 44 32 37 33 31 30 30 31 43 32 44 44 43 32 42 39 45 38 31 39 46 30 43 39 34 36 42 44 43 33 43 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {33 44 43 45 31 43 34 33 34 39 31 46 43 39 32 45 41 37 30 31 30 33 32 32 30 34 30 42 32 35 34 46 44 44 32 37 33 31 30 30 31 43 32 44 44 43 32 42 39 45 38 31 39 46 30 43 39 34 36 42 44 43 33 43 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\3DCE1C43491FC92EA7010322040B254FDD2731001C2DDC2B9E819F0C946BDC3C.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_KD_2147947220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.KD"
        threat_id = "2147947220"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:F79A71AD8BB2E3E7EDFC38970FDC05E922E429B5DFC325C7D0E91F216DE8F353" wide //weight: 1
        $x_1_2 = {46 37 39 41 37 31 41 44 38 42 42 32 45 33 45 37 45 44 46 43 33 38 39 37 30 46 44 43 30 35 45 39 32 32 45 34 32 39 42 35 44 46 43 33 32 35 43 37 44 30 45 39 31 46 32 31 36 44 45 38 46 33 35 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {46 37 39 41 37 31 41 44 38 42 42 32 45 33 45 37 45 44 46 43 33 38 39 37 30 46 44 43 30 35 45 39 32 32 45 34 32 39 42 35 44 46 43 33 32 35 43 37 44 30 45 39 31 46 32 31 36 44 45 38 46 33 35 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\F79A71AD8BB2E3E7EDFC38970FDC05E922E429B5DFC325C7D0E91F216DE8F353.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_KE_2147947224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.KE"
        threat_id = "2147947224"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:A1A6D2ECC8DB18DA0D5F04C5ED01A565B5A46E4012FAE627ACCB5D709BB89477" wide //weight: 1
        $x_1_2 = {41 31 41 36 44 32 45 43 43 38 44 42 31 38 44 41 30 44 35 46 30 34 43 35 45 44 30 31 41 35 36 35 42 35 41 34 36 45 34 30 31 32 46 41 45 36 32 37 41 43 43 42 35 44 37 30 39 42 42 38 39 34 37 37 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {41 31 41 36 44 32 45 43 43 38 44 42 31 38 44 41 30 44 35 46 30 34 43 35 45 44 30 31 41 35 36 35 42 35 41 34 36 45 34 30 31 32 46 41 45 36 32 37 41 43 43 42 35 44 37 30 39 42 42 38 39 34 37 37 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\A1A6D2ECC8DB18DA0D5F04C5ED01A565B5A46E4012FAE627ACCB5D709BB89477.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_KF_2147947228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.KF"
        threat_id = "2147947228"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:3DF86B12634F4308F81C86251AF940D8F6492A074C8C6F2EFA0D134F024A6E54" wide //weight: 1
        $x_1_2 = {33 44 46 38 36 42 31 32 36 33 34 46 34 33 30 38 46 38 31 43 38 36 32 35 31 41 46 39 34 30 44 38 46 36 34 39 32 41 30 37 34 43 38 43 36 46 32 45 46 41 30 44 31 33 34 46 30 32 34 41 36 45 35 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {33 44 46 38 36 42 31 32 36 33 34 46 34 33 30 38 46 38 31 43 38 36 32 35 31 41 46 39 34 30 44 38 46 36 34 39 32 41 30 37 34 43 38 43 36 46 32 45 46 41 30 44 31 33 34 46 30 32 34 41 36 45 35 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\3DF86B12634F4308F81C86251AF940D8F6492A074C8C6F2EFA0D134F024A6E54.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_KG_2147947559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.KG"
        threat_id = "2147947559"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:18ABE3218DA414FFE887EA63EEE8015840D37E607B4A558E8DDECCBC7835726B" wide //weight: 1
        $x_1_2 = {31 38 41 42 45 33 32 31 38 44 41 34 31 34 46 46 45 38 38 37 45 41 36 33 45 45 45 38 30 31 35 38 34 30 44 33 37 45 36 30 37 42 34 41 35 35 38 45 38 44 44 45 43 43 42 43 37 38 33 35 37 32 36 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {31 38 41 42 45 33 32 31 38 44 41 34 31 34 46 46 45 38 38 37 45 41 36 33 45 45 45 38 30 31 35 38 34 30 44 33 37 45 36 30 37 42 34 41 35 35 38 45 38 44 44 45 43 43 42 43 37 38 33 35 37 32 36 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\18ABE3218DA414FFE887EA63EEE8015840D37E607B4A558E8DDECCBC7835726B.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_KH_2147947563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.KH"
        threat_id = "2147947563"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:0E72456DFC641D0F0043DEBD2F43775500A4E04CE497DEC6D96B63F45D2DEF3C" wide //weight: 1
        $x_1_2 = {30 45 37 32 34 35 36 44 46 43 36 34 31 44 30 46 30 30 34 33 44 45 42 44 32 46 34 33 37 37 35 35 30 30 41 34 45 30 34 43 45 34 39 37 44 45 43 36 44 39 36 42 36 33 46 34 35 44 32 44 45 46 33 43 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {30 45 37 32 34 35 36 44 46 43 36 34 31 44 30 46 30 30 34 33 44 45 42 44 32 46 34 33 37 37 35 35 30 30 41 34 45 30 34 43 45 34 39 37 44 45 43 36 44 39 36 42 36 33 46 34 35 44 32 44 45 46 33 43 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\0E72456DFC641D0F0043DEBD2F43775500A4E04CE497DEC6D96B63F45D2DEF3C.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_KI_2147947567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.KI"
        threat_id = "2147947567"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:2E3FA2617E6992E79694AA7DE435E1211358858A039523F50DE5623E2DA7665B" wide //weight: 1
        $x_1_2 = {32 45 33 46 41 32 36 31 37 45 36 39 39 32 45 37 39 36 39 34 41 41 37 44 45 34 33 35 45 31 32 31 31 33 35 38 38 35 38 41 30 33 39 35 32 33 46 35 30 44 45 35 36 32 33 45 32 44 41 37 36 36 35 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {32 45 33 46 41 32 36 31 37 45 36 39 39 32 45 37 39 36 39 34 41 41 37 44 45 34 33 35 45 31 32 31 31 33 35 38 38 35 38 41 30 33 39 35 32 33 46 35 30 44 45 35 36 32 33 45 32 44 41 37 36 36 35 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\2E3FA2617E6992E79694AA7DE435E1211358858A039523F50DE5623E2DA7665B.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_KJ_2147947571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.KJ"
        threat_id = "2147947571"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:24B6401FEFBEAB90B409C221AC09C61AFC85F0D5A79A3AB68655F0D06DF65E6F" wide //weight: 1
        $x_1_2 = {32 34 42 36 34 30 31 46 45 46 42 45 41 42 39 30 42 34 30 39 43 32 32 31 41 43 30 39 43 36 31 41 46 43 38 35 46 30 44 35 41 37 39 41 33 41 42 36 38 36 35 35 46 30 44 30 36 44 46 36 35 45 36 46 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {32 34 42 36 34 30 31 46 45 46 42 45 41 42 39 30 42 34 30 39 43 32 32 31 41 43 30 39 43 36 31 41 46 43 38 35 46 30 44 35 41 37 39 41 33 41 42 36 38 36 35 35 46 30 44 30 36 44 46 36 35 45 36 46 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\24B6401FEFBEAB90B409C221AC09C61AFC85F0D5A79A3AB68655F0D06DF65E6F.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_KK_2147947575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.KK"
        threat_id = "2147947575"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:088B7708F2C1557B6023B1102FFC5C36C023FF4883CB073F26A33B73832C9268" wide //weight: 1
        $x_1_2 = {30 38 38 42 37 37 30 38 46 32 43 31 35 35 37 42 36 30 32 33 42 31 31 30 32 46 46 43 35 43 33 36 43 30 32 33 46 46 34 38 38 33 43 42 30 37 33 46 32 36 41 33 33 42 37 33 38 33 32 43 39 32 36 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {30 38 38 42 37 37 30 38 46 32 43 31 35 35 37 42 36 30 32 33 42 31 31 30 32 46 46 43 35 43 33 36 43 30 32 33 46 46 34 38 38 33 43 42 30 37 33 46 32 36 41 33 33 42 37 33 38 33 32 43 39 32 36 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\088B7708F2C1557B6023B1102FFC5C36C023FF4883CB073F26A33B73832C9268.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_KL_2147947579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.KL"
        threat_id = "2147947579"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:A0FE105A82525ECB94DD2977B4A1F8A5A7CF82F12D720DD8C8D9CCA3F98B6F52" wide //weight: 1
        $x_1_2 = {41 30 46 45 31 30 35 41 38 32 35 32 35 45 43 42 39 34 44 44 32 39 37 37 42 34 41 31 46 38 41 35 41 37 43 46 38 32 46 31 32 44 37 32 30 44 44 38 43 38 44 39 43 43 41 33 46 39 38 42 36 46 35 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {41 30 46 45 31 30 35 41 38 32 35 32 35 45 43 42 39 34 44 44 32 39 37 37 42 34 41 31 46 38 41 35 41 37 43 46 38 32 46 31 32 44 37 32 30 44 44 38 43 38 44 39 43 43 41 33 46 39 38 42 36 46 35 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\A0FE105A82525ECB94DD2977B4A1F8A5A7CF82F12D720DD8C8D9CCA3F98B6F52.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_KM_2147947583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.KM"
        threat_id = "2147947583"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:3820C40404684FFD4496CA1DA2F608374E60D1EA4628296D2AD1C31FE787EE4F" wide //weight: 1
        $x_1_2 = {33 38 32 30 43 34 30 34 30 34 36 38 34 46 46 44 34 34 39 36 43 41 31 44 41 32 46 36 30 38 33 37 34 45 36 30 44 31 45 41 34 36 32 38 32 39 36 44 32 41 44 31 43 33 31 46 45 37 38 37 45 45 34 46 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {33 38 32 30 43 34 30 34 30 34 36 38 34 46 46 44 34 34 39 36 43 41 31 44 41 32 46 36 30 38 33 37 34 45 36 30 44 31 45 41 34 36 32 38 32 39 36 44 32 41 44 31 43 33 31 46 45 37 38 37 45 45 34 46 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\3820C40404684FFD4496CA1DA2F608374E60D1EA4628296D2AD1C31FE787EE4F.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_KN_2147948025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.KN"
        threat_id = "2147948025"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:321CD8E65EF38ABEEEE190A65307B47AC80D088CAD7110EE8B2708E43150312B" wide //weight: 1
        $x_1_2 = {33 32 31 43 44 38 45 36 35 45 46 33 38 41 42 45 45 45 45 31 39 30 41 36 35 33 30 37 42 34 37 41 43 38 30 44 30 38 38 43 41 44 37 31 31 30 45 45 38 42 32 37 30 38 45 34 33 31 35 30 33 31 32 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {33 32 31 43 44 38 45 36 35 45 46 33 38 41 42 45 45 45 45 31 39 30 41 36 35 33 30 37 42 34 37 41 43 38 30 44 30 38 38 43 41 44 37 31 31 30 45 45 38 42 32 37 30 38 45 34 33 31 35 30 33 31 32 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\321CD8E65EF38ABEEEE190A65307B47AC80D088CAD7110EE8B2708E43150312B.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_KO_2147948371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.KO"
        threat_id = "2147948371"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:84490152E99B9EC4BCFE16080AFCFD6FDCD87512027E85DB318F7B3440982637" wide //weight: 1
        $x_1_2 = {38 34 34 39 30 31 35 32 45 39 39 42 39 45 43 34 42 43 46 45 31 36 30 38 30 41 46 43 46 44 36 46 44 43 44 38 37 35 31 32 30 32 37 45 38 35 44 42 33 31 38 46 37 42 33 34 34 30 39 38 32 36 33 37 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {38 34 34 39 30 31 35 32 45 39 39 42 39 45 43 34 42 43 46 45 31 36 30 38 30 41 46 43 46 44 36 46 44 43 44 38 37 35 31 32 30 32 37 45 38 35 44 42 33 31 38 46 37 42 33 34 34 30 39 38 32 36 33 37 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\84490152E99B9EC4BCFE16080AFCFD6FDCD87512027E85DB318F7B3440982637.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_KP_2147948787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.KP"
        threat_id = "2147948787"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:BD1B683FD3E6CB094341317A4C09923B7AE3E7903A6CDB90E5631EC7DC145263" wide //weight: 1
        $x_1_2 = {42 44 31 42 36 38 33 46 44 33 45 36 43 42 30 39 34 33 34 31 33 31 37 41 34 43 30 39 39 32 33 42 37 41 45 33 45 37 39 30 33 41 36 43 44 42 39 30 45 35 36 33 31 45 43 37 44 43 31 34 35 32 36 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {42 44 31 42 36 38 33 46 44 33 45 36 43 42 30 39 34 33 34 31 33 31 37 41 34 43 30 39 39 32 33 42 37 41 45 33 45 37 39 30 33 41 36 43 44 42 39 30 45 35 36 33 31 45 43 37 44 43 31 34 35 32 36 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\BD1B683FD3E6CB094341317A4C09923B7AE3E7903A6CDB90E5631EC7DC145263.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_KQ_2147948892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.KQ"
        threat_id = "2147948892"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:389EFCEB8DB8143C000A0A70B6C44A0436761784760F23E2F43A421F48A45D72" wide //weight: 1
        $x_1_2 = {33 38 39 45 46 43 45 42 38 44 42 38 31 34 33 43 30 30 30 41 30 41 37 30 42 36 43 34 34 41 30 34 33 36 37 36 31 37 38 34 37 36 30 46 32 33 45 32 46 34 33 41 34 32 31 46 34 38 41 34 35 44 37 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {33 38 39 45 46 43 45 42 38 44 42 38 31 34 33 43 30 30 30 41 30 41 37 30 42 36 43 34 34 41 30 34 33 36 37 36 31 37 38 34 37 36 30 46 32 33 45 32 46 34 33 41 34 32 31 46 34 38 41 34 35 44 37 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\389EFCEB8DB8143C000A0A70B6C44A0436761784760F23E2F43A421F48A45D72.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_KR_2147949021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.KR"
        threat_id = "2147949021"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:6BE80DE92BCBE49F0AD80AAEE5998991A4865700688093C881428F7617E69869" wide //weight: 1
        $x_1_2 = {36 42 45 38 30 44 45 39 32 42 43 42 45 34 39 46 30 41 44 38 30 41 41 45 45 35 39 39 38 39 39 31 41 34 38 36 35 37 30 30 36 38 38 30 39 33 43 38 38 31 34 32 38 46 37 36 31 37 45 36 39 38 36 39 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {36 42 45 38 30 44 45 39 32 42 43 42 45 34 39 46 30 41 44 38 30 41 41 45 45 35 39 39 38 39 39 31 41 34 38 36 35 37 30 30 36 38 38 30 39 33 43 38 38 31 34 32 38 46 37 36 31 37 45 36 39 38 36 39 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\6BE80DE92BCBE49F0AD80AAEE5998991A4865700688093C881428F7617E69869.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_KS_2147949025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.KS"
        threat_id = "2147949025"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:3B61CFD6E12D789A439816E1DE08CFDA58D76EB0B26585AA34CDA617C41D5943" wide //weight: 1
        $x_1_2 = {33 42 36 31 43 46 44 36 45 31 32 44 37 38 39 41 34 33 39 38 31 36 45 31 44 45 30 38 43 46 44 41 35 38 44 37 36 45 42 30 42 32 36 35 38 35 41 41 33 34 43 44 41 36 31 37 43 34 31 44 35 39 34 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {33 42 36 31 43 46 44 36 45 31 32 44 37 38 39 41 34 33 39 38 31 36 45 31 44 45 30 38 43 46 44 41 35 38 44 37 36 45 42 30 42 32 36 35 38 35 41 41 33 34 43 44 41 36 31 37 43 34 31 44 35 39 34 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\3B61CFD6E12D789A439816E1DE08CFDA58D76EB0B26585AA34CDA617C41D5943.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_KT_2147949040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.KT"
        threat_id = "2147949040"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:57A9B30B2D9E5F692A100C8E264082FC5F9B8F445C47E7333CBBB04DBF426400" wide //weight: 1
        $x_1_2 = {35 37 41 39 42 33 30 42 32 44 39 45 35 46 36 39 32 41 31 30 30 43 38 45 32 36 34 30 38 32 46 43 35 46 39 42 38 46 34 34 35 43 34 37 45 37 33 33 33 43 42 42 42 30 34 44 42 46 34 32 36 34 30 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {35 37 41 39 42 33 30 42 32 44 39 45 35 46 36 39 32 41 31 30 30 43 38 45 32 36 34 30 38 32 46 43 35 46 39 42 38 46 34 34 35 43 34 37 45 37 33 33 33 43 42 42 42 30 34 44 42 46 34 32 36 34 30 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\57A9B30B2D9E5F692A100C8E264082FC5F9B8F445C47E7333CBBB04DBF426400.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_KU_2147949059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.KU"
        threat_id = "2147949059"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:B64F3F32B8ADCB08945B1829D32AD024F63C4778C563B293A1F7D827D56AC454" wide //weight: 1
        $x_1_2 = {42 36 34 46 33 46 33 32 42 38 41 44 43 42 30 38 39 34 35 42 31 38 32 39 44 33 32 41 44 30 32 34 46 36 33 43 34 37 37 38 43 35 36 33 42 32 39 33 41 31 46 37 44 38 32 37 44 35 36 41 43 34 35 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {42 36 34 46 33 46 33 32 42 38 41 44 43 42 30 38 39 34 35 42 31 38 32 39 44 33 32 41 44 30 32 34 46 36 33 43 34 37 37 38 43 35 36 33 42 32 39 33 41 31 46 37 44 38 32 37 44 35 36 41 43 34 35 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\B64F3F32B8ADCB08945B1829D32AD024F63C4778C563B293A1F7D827D56AC454.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_KV_2147949731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.KV"
        threat_id = "2147949731"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:677DD06ED071E4B557FF3D9236ACD21AFECBA485C6643AB84F766060B967DC6E" wide //weight: 1
        $x_1_2 = {36 37 37 44 44 30 36 45 44 30 37 31 45 34 42 35 35 37 46 46 33 44 39 32 33 36 41 43 44 32 31 41 46 45 43 42 41 34 38 35 43 36 36 34 33 41 42 38 34 46 37 36 36 30 36 30 42 39 36 37 44 43 36 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {36 37 37 44 44 30 36 45 44 30 37 31 45 34 42 35 35 37 46 46 33 44 39 32 33 36 41 43 44 32 31 41 46 45 43 42 41 34 38 35 43 36 36 34 33 41 42 38 34 46 37 36 36 30 36 30 42 39 36 37 44 43 36 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\677DD06ED071E4B557FF3D9236ACD21AFECBA485C6643AB84F766060B967DC6E.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_KW_2147949797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.KW"
        threat_id = "2147949797"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:7BD82CCB3C2F4F4AD1400BF85701F82032665767C70A3D3B5F8957DE1383947B" wide //weight: 1
        $x_1_2 = {37 42 44 38 32 43 43 42 33 43 32 46 34 46 34 41 44 31 34 30 30 42 46 38 35 37 30 31 46 38 32 30 33 32 36 36 35 37 36 37 43 37 30 41 33 44 33 42 35 46 38 39 35 37 44 45 31 33 38 33 39 34 37 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {37 42 44 38 32 43 43 42 33 43 32 46 34 46 34 41 44 31 34 30 30 42 46 38 35 37 30 31 46 38 32 30 33 32 36 36 35 37 36 37 43 37 30 41 33 44 33 42 35 46 38 39 35 37 44 45 31 33 38 33 39 34 37 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\7BD82CCB3C2F4F4AD1400BF85701F82032665767C70A3D3B5F8957DE1383947B.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_KX_2147950813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.KX"
        threat_id = "2147950813"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:05FD37C2BDD09D597410C7B044FC871B0C1857DD667A1D8A1BD6E50500ECC906" wide //weight: 1
        $x_1_2 = {30 35 46 44 33 37 43 32 42 44 44 30 39 44 35 39 37 34 31 30 43 37 42 30 34 34 46 43 38 37 31 42 30 43 31 38 35 37 44 44 36 36 37 41 31 44 38 41 31 42 44 36 45 35 30 35 30 30 45 43 43 39 30 36 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {30 35 46 44 33 37 43 32 42 44 44 30 39 44 35 39 37 34 31 30 43 37 42 30 34 34 46 43 38 37 31 42 30 43 31 38 35 37 44 44 36 36 37 41 31 44 38 41 31 42 44 36 45 35 30 35 30 30 45 43 43 39 30 36 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\05FD37C2BDD09D597410C7B044FC871B0C1857DD667A1D8A1BD6E50500ECC906.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_KY_2147950853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.KY"
        threat_id = "2147950853"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:4D29BFBB2A354C58081B81AE2F1FED277C441E9C9BEBFA2D5BF55A4F5E614613" wide //weight: 1
        $x_1_2 = {34 44 32 39 42 46 42 42 32 41 33 35 34 43 35 38 30 38 31 42 38 31 41 45 32 46 31 46 45 44 32 37 37 43 34 34 31 45 39 43 39 42 45 42 46 41 32 44 35 42 46 35 35 41 34 46 35 45 36 31 34 36 31 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {34 44 32 39 42 46 42 42 32 41 33 35 34 43 35 38 30 38 31 42 38 31 41 45 32 46 31 46 45 44 32 37 37 43 34 34 31 45 39 43 39 42 45 42 46 41 32 44 35 42 46 35 35 41 34 46 35 45 36 31 34 36 31 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\4D29BFBB2A354C58081B81AE2F1FED277C441E9C9BEBFA2D5BF55A4F5E614613.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_KZ_2147951213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.KZ"
        threat_id = "2147951213"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:479C33961DCF60C10D3B131526CC9E0E7AF0684C4B3DCF34A20F2B61C92B691B" wide //weight: 1
        $x_1_2 = {34 37 39 43 33 33 39 36 31 44 43 46 36 30 43 31 30 44 33 42 31 33 31 35 32 36 43 43 39 45 30 45 37 41 46 30 36 38 34 43 34 42 33 44 43 46 33 34 41 32 30 46 32 42 36 31 43 39 32 42 36 39 31 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {34 37 39 43 33 33 39 36 31 44 43 46 36 30 43 31 30 44 33 42 31 33 31 35 32 36 43 43 39 45 30 45 37 41 46 30 36 38 34 43 34 42 33 44 43 46 33 34 41 32 30 46 32 42 36 31 43 39 32 42 36 39 31 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\479C33961DCF60C10D3B131526CC9E0E7AF0684C4B3DCF34A20F2B61C92B691B.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_LA_2147952911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.LA"
        threat_id = "2147952911"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:F8E24C7F5B12CD69C44C73F438F65E9BF560ADF35EBBDF92CF9A9B84079F8F04" wide //weight: 1
        $x_1_2 = {46 38 45 32 34 43 37 46 35 42 31 32 43 44 36 39 43 34 34 43 37 33 46 34 33 38 46 36 35 45 39 42 46 35 36 30 41 44 46 33 35 45 42 42 44 46 39 32 43 46 39 41 39 42 38 34 30 37 39 46 38 46 30 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {46 38 45 32 34 43 37 46 35 42 31 32 43 44 36 39 43 34 34 43 37 33 46 34 33 38 46 36 35 45 39 42 46 35 36 30 41 44 46 33 35 45 42 42 44 46 39 32 43 46 39 41 39 42 38 34 30 37 39 46 38 46 30 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\F8E24C7F5B12CD69C44C73F438F65E9BF560ADF35EBBDF92CF9A9B84079F8F04.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_LB_2147952915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.LB"
        threat_id = "2147952915"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:8F514E8FDA683D7C5957CE9560EB5941B4840DB0C3CEDEFB57FD8E2D8CF5884B" wide //weight: 1
        $x_1_2 = {38 46 35 31 34 45 38 46 44 41 36 38 33 44 37 43 35 39 35 37 43 45 39 35 36 30 45 42 35 39 34 31 42 34 38 34 30 44 42 30 43 33 43 45 44 45 46 42 35 37 46 44 38 45 32 44 38 43 46 35 38 38 34 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {38 46 35 31 34 45 38 46 44 41 36 38 33 44 37 43 35 39 35 37 43 45 39 35 36 30 45 42 35 39 34 31 42 34 38 34 30 44 42 30 43 33 43 45 44 45 46 42 35 37 46 44 38 45 32 44 38 43 46 35 38 38 34 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\8F514E8FDA683D7C5957CE9560EB5941B4840DB0C3CEDEFB57FD8E2D8CF5884B.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_LC_2147953082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.LC"
        threat_id = "2147953082"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:F97D66EB390592BA053CC7C25C16ECDBE42F3C266DD2A99CB9D1DDABE69F6A41" wide //weight: 1
        $x_1_2 = {46 39 37 44 36 36 45 42 33 39 30 35 39 32 42 41 30 35 33 43 43 37 43 32 35 43 31 36 45 43 44 42 45 34 32 46 33 43 32 36 36 44 44 32 41 39 39 43 42 39 44 31 44 44 41 42 45 36 39 46 36 41 34 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {46 39 37 44 36 36 45 42 33 39 30 35 39 32 42 41 30 35 33 43 43 37 43 32 35 43 31 36 45 43 44 42 45 34 32 46 33 43 32 36 36 44 44 32 41 39 39 43 42 39 44 31 44 44 41 42 45 36 39 46 36 41 34 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\F97D66EB390592BA053CC7C25C16ECDBE42F3C266DD2A99CB9D1DDABE69F6A41.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_LD_2147953965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.LD"
        threat_id = "2147953965"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:2996C1DF03CB26B174523ADA4C7832BD6122BA8F1BA86CD17CD102376E7C1B25" wide //weight: 1
        $x_1_2 = {32 39 39 36 43 31 44 46 30 33 43 42 32 36 42 31 37 34 35 32 33 41 44 41 34 43 37 38 33 32 42 44 36 31 32 32 42 41 38 46 31 42 41 38 36 43 44 31 37 43 44 31 30 32 33 37 36 45 37 43 31 42 32 35 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {32 39 39 36 43 31 44 46 30 33 43 42 32 36 42 31 37 34 35 32 33 41 44 41 34 43 37 38 33 32 42 44 36 31 32 32 42 41 38 46 31 42 41 38 36 43 44 31 37 43 44 31 30 32 33 37 36 45 37 43 31 42 32 35 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\2996C1DF03CB26B174523ADA4C7832BD6122BA8F1BA86CD17CD102376E7C1B25.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_LE_2147953969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.LE"
        threat_id = "2147953969"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:CC7E1D4845641E2AC5B6D137E68292E85F44760038F83CE96D7236AB0393FE0B" wide //weight: 1
        $x_1_2 = {43 43 37 45 31 44 34 38 34 35 36 34 31 45 32 41 43 35 42 36 44 31 33 37 45 36 38 32 39 32 45 38 35 46 34 34 37 36 30 30 33 38 46 38 33 43 45 39 36 44 37 32 33 36 41 42 30 33 39 33 46 45 30 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {43 43 37 45 31 44 34 38 34 35 36 34 31 45 32 41 43 35 42 36 44 31 33 37 45 36 38 32 39 32 45 38 35 46 34 34 37 36 30 30 33 38 46 38 33 43 45 39 36 44 37 32 33 36 41 42 30 33 39 33 46 45 30 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\CC7E1D4845641E2AC5B6D137E68292E85F44760038F83CE96D7236AB0393FE0B.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_LF_2147953973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.LF"
        threat_id = "2147953973"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:D9E5193C2C7FE289725AF2CCB8FA7744DD0175F478050196994AE77DCAA8621D" wide //weight: 1
        $x_1_2 = {44 39 45 35 31 39 33 43 32 43 37 46 45 32 38 39 37 32 35 41 46 32 43 43 42 38 46 41 37 37 34 34 44 44 30 31 37 35 46 34 37 38 30 35 30 31 39 36 39 39 34 41 45 37 37 44 43 41 41 38 36 32 31 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {44 39 45 35 31 39 33 43 32 43 37 46 45 32 38 39 37 32 35 41 46 32 43 43 42 38 46 41 37 37 34 34 44 44 30 31 37 35 46 34 37 38 30 35 30 31 39 36 39 39 34 41 45 37 37 44 43 41 41 38 36 32 31 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\D9E5193C2C7FE289725AF2CCB8FA7744DD0175F478050196994AE77DCAA8621D.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_LG_2147954455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.LG"
        threat_id = "2147954455"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:1C069B583BBCF41A918EF3C489898735744F5C3E81B2DDF91ADEA6BA33D4A594" wide //weight: 1
        $x_1_2 = {31 43 30 36 39 42 35 38 33 42 42 43 46 34 31 41 39 31 38 45 46 33 43 34 38 39 38 39 38 37 33 35 37 34 34 46 35 43 33 45 38 31 42 32 44 44 46 39 31 41 44 45 41 36 42 41 33 33 44 34 41 35 39 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {31 43 30 36 39 42 35 38 33 42 42 43 46 34 31 41 39 31 38 45 46 33 43 34 38 39 38 39 38 37 33 35 37 34 34 46 35 43 33 45 38 31 42 32 44 44 46 39 31 41 44 45 41 36 42 41 33 33 44 34 41 35 39 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\1C069B583BBCF41A918EF3C489898735744F5C3E81B2DDF91ADEA6BA33D4A594.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_LH_2147954459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.LH"
        threat_id = "2147954459"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:F92557C3FE2EB389DA1EB0D2FBE83B9CBACC13FB823918DAC58184B9D27CF72C" wide //weight: 1
        $x_1_2 = {46 39 32 35 35 37 43 33 46 45 32 45 42 33 38 39 44 41 31 45 42 30 44 32 46 42 45 38 33 42 39 43 42 41 43 43 31 33 46 42 38 32 33 39 31 38 44 41 43 35 38 31 38 34 42 39 44 32 37 43 46 37 32 43 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {46 39 32 35 35 37 43 33 46 45 32 45 42 33 38 39 44 41 31 45 42 30 44 32 46 42 45 38 33 42 39 43 42 41 43 43 31 33 46 42 38 32 33 39 31 38 44 41 43 35 38 31 38 34 42 39 44 32 37 43 46 37 32 43 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\F92557C3FE2EB389DA1EB0D2FBE83B9CBACC13FB823918DAC58184B9D27CF72C.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_LI_2147954481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.LI"
        threat_id = "2147954481"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:AA406E661AF60F4D89E012CB7C5B33CAFAEEFE92AE3DA43F8890CEB405015B79" wide //weight: 1
        $x_1_2 = {41 41 34 30 36 45 36 36 31 41 46 36 30 46 34 44 38 39 45 30 31 32 43 42 37 43 35 42 33 33 43 41 46 41 45 45 46 45 39 32 41 45 33 44 41 34 33 46 38 38 39 30 43 45 42 34 30 35 30 31 35 42 37 39 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {41 41 34 30 36 45 36 36 31 41 46 36 30 46 34 44 38 39 45 30 31 32 43 42 37 43 35 42 33 33 43 41 46 41 45 45 46 45 39 32 41 45 33 44 41 34 33 46 38 38 39 30 43 45 42 34 30 35 30 31 35 42 37 39 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\AA406E661AF60F4D89E012CB7C5B33CAFAEEFE92AE3DA43F8890CEB405015B79.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_LJ_2147954485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.LJ"
        threat_id = "2147954485"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:F7651F08BF8F487D17AC28BF34DD2EAAAA2FB1867DC5891030985F5E0979A858" wide //weight: 1
        $x_1_2 = {46 37 36 35 31 46 30 38 42 46 38 46 34 38 37 44 31 37 41 43 32 38 42 46 33 34 44 44 32 45 41 41 41 41 32 46 42 31 38 36 37 44 43 35 38 39 31 30 33 30 39 38 35 46 35 45 30 39 37 39 41 38 35 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {46 37 36 35 31 46 30 38 42 46 38 46 34 38 37 44 31 37 41 43 32 38 42 46 33 34 44 44 32 45 41 41 41 41 32 46 42 31 38 36 37 44 43 35 38 39 31 30 33 30 39 38 35 46 35 45 30 39 37 39 41 38 35 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\F7651F08BF8F487D17AC28BF34DD2EAAAA2FB1867DC5891030985F5E0979A858.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_LK_2147954851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.LK"
        threat_id = "2147954851"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:EFE1A6E5C8AF91FB1EA3A170823F5E69A85F866CF33A4370EC46747491694104" wide //weight: 1
        $x_1_2 = {45 46 45 31 41 36 45 35 43 38 41 46 39 31 46 42 31 45 41 33 41 31 37 30 38 32 33 46 35 45 36 39 41 38 35 46 38 36 36 43 46 33 33 41 34 33 37 30 45 43 34 36 37 34 37 34 39 31 36 39 34 31 30 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {45 46 45 31 41 36 45 35 43 38 41 46 39 31 46 42 31 45 41 33 41 31 37 30 38 32 33 46 35 45 36 39 41 38 35 46 38 36 36 43 46 33 33 41 34 33 37 30 45 43 34 36 37 34 37 34 39 31 36 39 34 31 30 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\EFE1A6E5C8AF91FB1EA3A170823F5E69A85F866CF33A4370EC46747491694104.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_LL_2147955097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.LL"
        threat_id = "2147955097"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:75E0FB17710F7C72DC454CE11EF4E4E13B074C6E0AC3A4C0A00A2E3A0165C334" wide //weight: 1
        $x_1_2 = {37 35 45 30 46 42 31 37 37 31 30 46 37 43 37 32 44 43 34 35 34 43 45 31 31 45 46 34 45 34 45 31 33 42 30 37 34 43 36 45 30 41 43 33 41 34 43 30 41 30 30 41 32 45 33 41 30 31 36 35 43 33 33 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {37 35 45 30 46 42 31 37 37 31 30 46 37 43 37 32 44 43 34 35 34 43 45 31 31 45 46 34 45 34 45 31 33 42 30 37 34 43 36 45 30 41 43 33 41 34 43 30 41 30 30 41 32 45 33 41 30 31 36 35 43 33 33 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\75E0FB17710F7C72DC454CE11EF4E4E13B074C6E0AC3A4C0A00A2E3A0165C334.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_LM_2147955261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.LM"
        threat_id = "2147955261"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:1CD56512F07E9459FD57FD834C2B3C1037FF1482D9AF211CB6C21AC5367E6108" wide //weight: 1
        $x_1_2 = {31 43 44 35 36 35 31 32 46 30 37 45 39 34 35 39 46 44 35 37 46 44 38 33 34 43 32 42 33 43 31 30 33 37 46 46 31 34 38 32 44 39 41 46 32 31 31 43 42 36 43 32 31 41 43 35 33 36 37 45 36 31 30 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {31 43 44 35 36 35 31 32 46 30 37 45 39 34 35 39 46 44 35 37 46 44 38 33 34 43 32 42 33 43 31 30 33 37 46 46 31 34 38 32 44 39 41 46 32 31 31 43 42 36 43 32 31 41 43 35 33 36 37 45 36 31 30 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\1CD56512F07E9459FD57FD834C2B3C1037FF1482D9AF211CB6C21AC5367E6108.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_LN_2147955265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.LN"
        threat_id = "2147955265"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:138A7107FE83F6CBC03A43D484C17CCBF7E6ED5060792D6AFB1BE4358FB94828" wide //weight: 1
        $x_1_2 = {31 33 38 41 37 31 30 37 46 45 38 33 46 36 43 42 43 30 33 41 34 33 44 34 38 34 43 31 37 43 43 42 46 37 45 36 45 44 35 30 36 30 37 39 32 44 36 41 46 42 31 42 45 34 33 35 38 46 42 39 34 38 32 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {31 33 38 41 37 31 30 37 46 45 38 33 46 36 43 42 43 30 33 41 34 33 44 34 38 34 43 31 37 43 43 42 46 37 45 36 45 44 35 30 36 30 37 39 32 44 36 41 46 42 31 42 45 34 33 35 38 46 42 39 34 38 32 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\138A7107FE83F6CBC03A43D484C17CCBF7E6ED5060792D6AFB1BE4358FB94828.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_LO_2147956143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.LO"
        threat_id = "2147956143"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:78FE40161EED39FA9F3295E36E858537C5103ADB3E92E676EE97DF6C0B22C540" wide //weight: 1
        $x_1_2 = {37 38 46 45 34 30 31 36 31 45 45 44 33 39 46 41 39 46 33 32 39 35 45 33 36 45 38 35 38 35 33 37 43 35 31 30 33 41 44 42 33 45 39 32 45 36 37 36 45 45 39 37 44 46 36 43 30 42 32 32 43 35 34 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {37 38 46 45 34 30 31 36 31 45 45 44 33 39 46 41 39 46 33 32 39 35 45 33 36 45 38 35 38 35 33 37 43 35 31 30 33 41 44 42 33 45 39 32 45 36 37 36 45 45 39 37 44 46 36 43 30 42 32 32 43 35 34 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\78FE40161EED39FA9F3295E36E858537C5103ADB3E92E676EE97DF6C0B22C540.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_LP_2147956988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.LP"
        threat_id = "2147956988"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:AE55FC0EB1C25A5B081650108F9081E236DECE1CE08D2E185A6F15B9FB48E700" wide //weight: 1
        $x_1_2 = {41 45 35 35 46 43 30 45 42 31 43 32 35 41 35 42 30 38 31 36 35 30 31 30 38 46 39 30 38 31 45 32 33 36 44 45 43 45 31 43 45 30 38 44 32 45 31 38 35 41 36 46 31 35 42 39 46 42 34 38 45 37 30 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {41 45 35 35 46 43 30 45 42 31 43 32 35 41 35 42 30 38 31 36 35 30 31 30 38 46 39 30 38 31 45 32 33 36 44 45 43 45 31 43 45 30 38 44 32 45 31 38 35 41 36 46 31 35 42 39 46 42 34 38 45 37 30 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\AE55FC0EB1C25A5B081650108F9081E236DECE1CE08D2E185A6F15B9FB48E700.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_LQ_2147957642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.LQ"
        threat_id = "2147957642"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:E613311EB1CFE0A572A98DB678F58B42375129FDAF56426491098A3CA8D6605E" wide //weight: 1
        $x_1_2 = {45 36 31 33 33 31 31 45 42 31 43 46 45 30 41 35 37 32 41 39 38 44 42 36 37 38 46 35 38 42 34 32 33 37 35 31 32 39 46 44 41 46 35 36 34 32 36 34 39 31 30 39 38 41 33 43 41 38 44 36 36 30 35 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {45 36 31 33 33 31 31 45 42 31 43 46 45 30 41 35 37 32 41 39 38 44 42 36 37 38 46 35 38 42 34 32 33 37 35 31 32 39 46 44 41 46 35 36 34 32 36 34 39 31 30 39 38 41 33 43 41 38 44 36 36 30 35 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\E613311EB1CFE0A572A98DB678F58B42375129FDAF56426491098A3CA8D6605E.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_LR_2147957832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.LR"
        threat_id = "2147957832"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:C286720F7592E5668A932F1D06EDEECBAFACB3BE369632C908F9511D072C1425" wide //weight: 1
        $x_1_2 = {43 32 38 36 37 32 30 46 37 35 39 32 45 35 36 36 38 41 39 33 32 46 31 44 30 36 45 44 45 45 43 42 41 46 41 43 42 33 42 45 33 36 39 36 33 32 43 39 30 38 46 39 35 31 31 44 30 37 32 43 31 34 32 35 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {43 32 38 36 37 32 30 46 37 35 39 32 45 35 36 36 38 41 39 33 32 46 31 44 30 36 45 44 45 45 43 42 41 46 41 43 42 33 42 45 33 36 39 36 33 32 43 39 30 38 46 39 35 31 31 44 30 37 32 43 31 34 32 35 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\C286720F7592E5668A932F1D06EDEECBAFACB3BE369632C908F9511D072C1425.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_LS_2147957836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.LS"
        threat_id = "2147957836"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:0E67D9C77F417ABA9564B97C616A6ADAEDC2D3B2CD32B4868FD65E661F6C7931" wide //weight: 1
        $x_1_2 = {30 45 36 37 44 39 43 37 37 46 34 31 37 41 42 41 39 35 36 34 42 39 37 43 36 31 36 41 36 41 44 41 45 44 43 32 44 33 42 32 43 44 33 32 42 34 38 36 38 46 44 36 35 45 36 36 31 46 36 43 37 39 33 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {30 45 36 37 44 39 43 37 37 46 34 31 37 41 42 41 39 35 36 34 42 39 37 43 36 31 36 41 36 41 44 41 45 44 43 32 44 33 42 32 43 44 33 32 42 34 38 36 38 46 44 36 35 45 36 36 31 46 36 43 37 39 33 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\0E67D9C77F417ABA9564B97C616A6ADAEDC2D3B2CD32B4868FD65E661F6C7931.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_LT_2147957958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.LT"
        threat_id = "2147957958"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:605F934CBF207ACB81EBA316A5C78F2F4994AD5F2E14C395A9BBF1BA7E2B7004" wide //weight: 1
        $x_1_2 = {36 30 35 46 39 33 34 43 42 46 32 30 37 41 43 42 38 31 45 42 41 33 31 36 41 35 43 37 38 46 32 46 34 39 39 34 41 44 35 46 32 45 31 34 43 33 39 35 41 39 42 42 46 31 42 41 37 45 32 42 37 30 30 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {36 30 35 46 39 33 34 43 42 46 32 30 37 41 43 42 38 31 45 42 41 33 31 36 41 35 43 37 38 46 32 46 34 39 39 34 41 44 35 46 32 45 31 34 43 33 39 35 41 39 42 42 46 31 42 41 37 45 32 42 37 30 30 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\605F934CBF207ACB81EBA316A5C78F2F4994AD5F2E14C395A9BBF1BA7E2B7004.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_LU_2147958049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.LU"
        threat_id = "2147958049"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:CB30FE751B15511AC8ABC696923F49CD3CE4C68E67E8391DA57CEC0ECFDE3E4F" wide //weight: 1
        $x_1_2 = {43 42 33 30 46 45 37 35 31 42 31 35 35 31 31 41 43 38 41 42 43 36 39 36 39 32 33 46 34 39 43 44 33 43 45 34 43 36 38 45 36 37 45 38 33 39 31 44 41 35 37 43 45 43 30 45 43 46 44 45 33 45 34 46 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {43 42 33 30 46 45 37 35 31 42 31 35 35 31 31 41 43 38 41 42 43 36 39 36 39 32 33 46 34 39 43 44 33 43 45 34 43 36 38 45 36 37 45 38 33 39 31 44 41 35 37 43 45 43 30 45 43 46 44 45 33 45 34 46 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\CB30FE751B15511AC8ABC696923F49CD3CE4C68E67E8391DA57CEC0ECFDE3E4F.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_LV_2147958054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.LV"
        threat_id = "2147958054"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:F357E5DFC995E725B1DCA2E153C44602FB1A04F4047715B907553F9ED3A2E87D" wide //weight: 1
        $x_1_2 = {46 33 35 37 45 35 44 46 43 39 39 35 45 37 32 35 42 31 44 43 41 32 45 31 35 33 43 34 34 36 30 32 46 42 31 41 30 34 46 34 30 34 37 37 31 35 42 39 30 37 35 35 33 46 39 45 44 33 41 32 45 38 37 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {46 33 35 37 45 35 44 46 43 39 39 35 45 37 32 35 42 31 44 43 41 32 45 31 35 33 43 34 34 36 30 32 46 42 31 41 30 34 46 34 30 34 37 37 31 35 42 39 30 37 35 35 33 46 39 45 44 33 41 32 45 38 37 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\F357E5DFC995E725B1DCA2E153C44602FB1A04F4047715B907553F9ED3A2E87D.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_LW_2147958082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.LW"
        threat_id = "2147958082"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:B2C186BC563089FBE6553387E1BFFE6D3663A13392C9D4F985972D7E5C1BA00A" wide //weight: 1
        $x_1_2 = {42 32 43 31 38 36 42 43 35 36 33 30 38 39 46 42 45 36 35 35 33 33 38 37 45 31 42 46 46 45 36 44 33 36 36 33 41 31 33 33 39 32 43 39 44 34 46 39 38 35 39 37 32 44 37 45 35 43 31 42 41 30 30 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {42 32 43 31 38 36 42 43 35 36 33 30 38 39 46 42 45 36 35 35 33 33 38 37 45 31 42 46 46 45 36 44 33 36 36 33 41 31 33 33 39 32 43 39 44 34 46 39 38 35 39 37 32 44 37 45 35 43 31 42 41 30 30 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\B2C186BC563089FBE6553387E1BFFE6D3663A13392C9D4F985972D7E5C1BA00A.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_LX_2147958086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.LX"
        threat_id = "2147958086"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:5FECF5D7BC4E86A5483E332A937C35EE171A953EAAABE967A23DD9779BD6D30D" wide //weight: 1
        $x_1_2 = {35 46 45 43 46 35 44 37 42 43 34 45 38 36 41 35 34 38 33 45 33 33 32 41 39 33 37 43 33 35 45 45 31 37 31 41 39 35 33 45 41 41 41 42 45 39 36 37 41 32 33 44 44 39 37 37 39 42 44 36 44 33 30 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {35 46 45 43 46 35 44 37 42 43 34 45 38 36 41 35 34 38 33 45 33 33 32 41 39 33 37 43 33 35 45 45 31 37 31 41 39 35 33 45 41 41 41 42 45 39 36 37 41 32 33 44 44 39 37 37 39 42 44 36 44 33 30 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\5FECF5D7BC4E86A5483E332A937C35EE171A953EAAABE967A23DD9779BD6D30D.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_LY_2147958090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.LY"
        threat_id = "2147958090"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:B15603A26277461D91AAE8F00547F27F9BAABF5C72BCFB80814206D5F18BE723" wide //weight: 1
        $x_1_2 = {42 31 35 36 30 33 41 32 36 32 37 37 34 36 31 44 39 31 41 41 45 38 46 30 30 35 34 37 46 32 37 46 39 42 41 41 42 46 35 43 37 32 42 43 46 42 38 30 38 31 34 32 30 36 44 35 46 31 38 42 45 37 32 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {42 31 35 36 30 33 41 32 36 32 37 37 34 36 31 44 39 31 41 41 45 38 46 30 30 35 34 37 46 32 37 46 39 42 41 41 42 46 35 43 37 32 42 43 46 42 38 30 38 31 34 32 30 36 44 35 46 31 38 42 45 37 32 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\B15603A26277461D91AAE8F00547F27F9BAABF5C72BCFB80814206D5F18BE723.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_LZ_2147958094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.LZ"
        threat_id = "2147958094"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:5D2C1252652307D991BB2C63872683D3C68D640A5E67DDF78A8C8EB9815DFC77" wide //weight: 1
        $x_1_2 = {35 44 32 43 31 32 35 32 36 35 32 33 30 37 44 39 39 31 42 42 32 43 36 33 38 37 32 36 38 33 44 33 43 36 38 44 36 34 30 41 35 45 36 37 44 44 46 37 38 41 38 43 38 45 42 39 38 31 35 44 46 43 37 37 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {35 44 32 43 31 32 35 32 36 35 32 33 30 37 44 39 39 31 42 42 32 43 36 33 38 37 32 36 38 33 44 33 43 36 38 44 36 34 30 41 35 45 36 37 44 44 46 37 38 41 38 43 38 45 42 39 38 31 35 44 46 43 37 37 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\5D2C1252652307D991BB2C63872683D3C68D640A5E67DDF78A8C8EB9815DFC77.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_MA_2147958098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.MA"
        threat_id = "2147958098"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:9E95D4A886F6678290331E41FED1C9C41C48554905087DEA05E78C8254905C0C" wide //weight: 1
        $x_1_2 = {39 45 39 35 44 34 41 38 38 36 46 36 36 37 38 32 39 30 33 33 31 45 34 31 46 45 44 31 43 39 43 34 31 43 34 38 35 35 34 39 30 35 30 38 37 44 45 41 30 35 45 37 38 43 38 32 35 34 39 30 35 43 30 43 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {39 45 39 35 44 34 41 38 38 36 46 36 36 37 38 32 39 30 33 33 31 45 34 31 46 45 44 31 43 39 43 34 31 43 34 38 35 35 34 39 30 35 30 38 37 44 45 41 30 35 45 37 38 43 38 32 35 34 39 30 35 43 30 43 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\9E95D4A886F6678290331E41FED1C9C41C48554905087DEA05E78C8254905C0C.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_MB_2147959039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.MB"
        threat_id = "2147959039"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:0520B56A668EE2349255CA2FFDEBDA61323169F7862CD017F300C2630BD56227" wide //weight: 1
        $x_1_2 = {30 35 32 30 42 35 36 41 36 36 38 45 45 32 33 34 39 32 35 35 43 41 32 46 46 44 45 42 44 41 36 31 33 32 33 31 36 39 46 37 38 36 32 43 44 30 31 37 46 33 30 30 43 32 36 33 30 42 44 35 36 32 32 37 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {30 35 32 30 42 35 36 41 36 36 38 45 45 32 33 34 39 32 35 35 43 41 32 46 46 44 45 42 44 41 36 31 33 32 33 31 36 39 46 37 38 36 32 43 44 30 31 37 46 33 30 30 43 32 36 33 30 42 44 35 36 32 32 37 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\0520B56A668EE2349255CA2FFDEBDA61323169F7862CD017F300C2630BD56227.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_MC_2147959434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.MC"
        threat_id = "2147959434"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:5D16859E0BC70E8830DEB8DE294C7E5AF8BD4D30CB1CB01F3BE17D0F592B3264" wide //weight: 1
        $x_1_2 = {35 44 31 36 38 35 39 45 30 42 43 37 30 45 38 38 33 30 44 45 42 38 44 45 32 39 34 43 37 45 35 41 46 38 42 44 34 44 33 30 43 42 31 43 42 30 31 46 33 42 45 31 37 44 30 46 35 39 32 42 33 32 36 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {35 44 31 36 38 35 39 45 30 42 43 37 30 45 38 38 33 30 44 45 42 38 44 45 32 39 34 43 37 45 35 41 46 38 42 44 34 44 33 30 43 42 31 43 42 30 31 46 33 42 45 31 37 44 30 46 35 39 32 42 33 32 36 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\5D16859E0BC70E8830DEB8DE294C7E5AF8BD4D30CB1CB01F3BE17D0F592B3264.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_MD_2147959438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.MD"
        threat_id = "2147959438"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:8AE76D106C7F34134CAB98E41C5EEEF15B238BC523EC2F09C7765214CB038228" wide //weight: 1
        $x_1_2 = {38 41 45 37 36 44 31 30 36 43 37 46 33 34 31 33 34 43 41 42 39 38 45 34 31 43 35 45 45 45 46 31 35 42 32 33 38 42 43 35 32 33 45 43 32 46 30 39 43 37 37 36 35 32 31 34 43 42 30 33 38 32 32 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {38 41 45 37 36 44 31 30 36 43 37 46 33 34 31 33 34 43 41 42 39 38 45 34 31 43 35 45 45 45 46 31 35 42 32 33 38 42 43 35 32 33 45 43 32 46 30 39 43 37 37 36 35 32 31 34 43 42 30 33 38 32 32 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\8AE76D106C7F34134CAB98E41C5EEEF15B238BC523EC2F09C7765214CB038228.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommMain_ME_2147959442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommMain.ME"
        threat_id = "2147959442"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tox:9897B2686C5256F5CA6A3AE7654DEF62A7E839DC54193D37D0CE5FFCAEC4A042" wide //weight: 1
        $x_1_2 = {39 38 39 37 42 32 36 38 36 43 35 32 35 36 46 35 43 41 36 41 33 41 45 37 36 35 34 44 45 46 36 32 41 37 45 38 33 39 44 43 35 34 31 39 33 44 33 37 44 30 43 45 35 46 46 43 41 45 43 34 41 30 34 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {39 38 39 37 42 32 36 38 36 43 35 32 35 36 46 35 43 41 36 41 33 41 45 37 36 35 34 44 45 46 36 32 41 37 45 38 33 39 44 43 35 34 31 39 33 44 33 37 44 30 43 45 35 46 46 43 41 45 43 34 41 30 34 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\tox\\9897B2686C5256F5CA6A3AE7654DEF62A7E839DC54193D37D0CE5FFCAEC4A042.hstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

