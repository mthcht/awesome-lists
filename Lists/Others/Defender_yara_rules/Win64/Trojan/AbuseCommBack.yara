rule Trojan_Win64_AbuseCommBack_A_2147824257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.A"
        threat_id = "2147824257"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 30 38 35 42 38 39 41 30 43 35 31 35 44 32 46 42 31 32 34 44 36 34 35 39 30 36 46 35 44 33 44 41 35 43 42 39 37 43 45 42 45 41 39 37 35 39 35 39 41 45 34 46 39 35 33 30 32 41 30 34 45 31 44 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "<p>3085B89A0C515D2FB124D645906F5D3DA5CB97CEBEA975959AE4F95302A04E1D</p>" wide //weight: 1
        $x_1_3 = "tableid3085B89A0C515D2FB124D645906F5D3DA5CB97CEBEA975959AE4F95302A04E1Did" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_B_2147824928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.B"
        threat_id = "2147824928"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>8BEDC411012A33BA34F49130D0F186993C6A32DAD8976F6A5D82C1ED23054C05</p>" wide //weight: 1
        $x_1_2 = {38 42 45 44 43 34 31 31 30 31 32 41 33 33 42 41 33 34 46 34 39 31 33 30 44 30 46 31 38 36 39 39 33 43 36 41 33 32 44 41 44 38 39 37 36 46 36 41 35 44 38 32 43 31 45 44 32 33 30 35 34 43 30 35 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid8BEDC411012A33BA34F49130D0F186993C6A32DAD8976F6A5D82C1ED23054C05id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_C_2147824932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.C"
        threat_id = "2147824932"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>3728E933284CE638D06FCF1CBE921096E102508BD370D6D23137D3271EE57338</p>" wide //weight: 1
        $x_1_2 = {33 37 32 38 45 39 33 33 32 38 34 43 45 36 33 38 44 30 36 46 43 46 31 43 42 45 39 32 31 30 39 36 45 31 30 32 35 30 38 42 44 33 37 30 44 36 44 32 33 31 33 37 44 33 32 37 31 45 45 35 37 33 33 38 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid3728E933284CE638D06FCF1CBE921096E102508BD370D6D23137D3271EE57338id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_D_2147824936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.D"
        threat_id = "2147824936"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>81B2B719AB9BDDCE9116776FA01956C2D4BB8A7CA5464592593F9A25DA1F9117</p>" wide //weight: 1
        $x_1_2 = {38 31 42 32 42 37 31 39 41 42 39 42 44 44 43 45 39 31 31 36 37 37 36 46 41 30 31 39 35 36 43 32 44 34 42 42 38 41 37 43 41 35 34 36 34 35 39 32 35 39 33 46 39 41 32 35 44 41 31 46 39 31 31 37 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid81B2B719AB9BDDCE9116776FA01956C2D4BB8A7CA5464592593F9A25DA1F9117id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_E_2147824940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.E"
        threat_id = "2147824940"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>6F548F217897AA4140FB4C514C8187F2FFDBA3CAFC83795DEE2FBCA369E68900</p>" wide //weight: 1
        $x_1_2 = {36 46 35 34 38 46 32 31 37 38 39 37 41 41 34 31 34 30 46 42 34 43 35 31 34 43 38 31 38 37 46 32 46 46 44 42 41 33 43 41 46 43 38 33 37 39 35 44 45 45 32 46 42 43 41 33 36 39 45 36 38 39 30 30 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid6F548F217897AA4140FB4C514C8187F2FFDBA3CAFC83795DEE2FBCA369E68900id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_F_2147826171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.F"
        threat_id = "2147826171"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>35F36AF07A7FD5232EB10F69DB4A6FB4AFA54A88357F0CD23816A6756FAA6F1E</p>" wide //weight: 1
        $x_1_2 = {33 35 46 33 36 41 46 30 37 41 37 46 44 35 32 33 32 45 42 31 30 46 36 39 44 42 34 41 36 46 42 34 41 46 41 35 34 41 38 38 33 35 37 46 30 43 44 32 33 38 31 36 41 36 37 35 36 46 41 41 36 46 31 45 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid35F36AF07A7FD5232EB10F69DB4A6FB4AFA54A88357F0CD23816A6756FAA6F1Eid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_G_2147826175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.G"
        threat_id = "2147826175"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>6C5AD4057E594E090E0C987B3089F74335DA75F04B7403E0575663C261349569</p>" wide //weight: 1
        $x_1_2 = {36 43 35 41 44 34 30 35 37 45 35 39 34 45 30 39 30 45 30 43 39 38 37 42 33 30 38 39 46 37 34 33 33 35 44 41 37 35 46 30 34 42 37 34 30 33 45 30 35 37 35 36 36 33 43 32 36 31 33 34 39 35 36 39 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid6C5AD4057E594E090E0C987B3089F74335DA75F04B7403E0575663C261349569id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_H_2147826984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.H"
        threat_id = "2147826984"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>0FF26770BFAEAD95194506E6970CC1C395B04159038D785DE316F05CE6DE6732</p>" wide //weight: 1
        $x_1_2 = {30 46 46 32 36 37 37 30 42 46 41 45 41 44 39 35 31 39 34 35 30 36 45 36 39 37 30 43 43 31 43 33 39 35 42 30 34 31 35 39 30 33 38 44 37 38 35 44 45 33 31 36 46 30 35 43 45 36 44 45 36 37 33 32 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid0FF26770BFAEAD95194506E6970CC1C395B04159038D785DE316F05CE6DE6732id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_I_2147826988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.I"
        threat_id = "2147826988"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>BBA99964ECC6CA4A8B6460FB0CB45AD8781AC01D94F6F6DBF9B9D1202BAF1822</p>" wide //weight: 1
        $x_1_2 = {42 42 41 39 39 39 36 34 45 43 43 36 43 41 34 41 38 42 36 34 36 30 46 42 30 43 42 34 35 41 44 38 37 38 31 41 43 30 31 44 39 34 46 36 46 36 44 42 46 39 42 39 44 31 32 30 32 42 41 46 31 38 32 32 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidBBA99964ECC6CA4A8B6460FB0CB45AD8781AC01D94F6F6DBF9B9D1202BAF1822id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_J_2147827313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.J"
        threat_id = "2147827313"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>F17A21223580DBB02D4FA592B5568B09594B7A90BA21C31534BF2EF7D3082C29</p>" wide //weight: 1
        $x_1_2 = {46 31 37 41 32 31 32 32 33 35 38 30 44 42 42 30 32 44 34 46 41 35 39 32 42 35 35 36 38 42 30 39 35 39 34 42 37 41 39 30 42 41 32 31 43 33 31 35 33 34 42 46 32 45 46 37 44 33 30 38 32 43 32 39 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidF17A21223580DBB02D4FA592B5568B09594B7A90BA21C31534BF2EF7D3082C29id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_K_2147827317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.K"
        threat_id = "2147827317"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>10D20B109E895D2FBC70F11E9A775825E9397B0B89FE00FDD96BA8158F8A542A</p>" wide //weight: 1
        $x_1_2 = {31 30 44 32 30 42 31 30 39 45 38 39 35 44 32 46 42 43 37 30 46 31 31 45 39 41 37 37 35 38 32 35 45 39 33 39 37 42 30 42 38 39 46 45 30 30 46 44 44 39 36 42 41 38 31 35 38 46 38 41 35 34 32 41 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid10D20B109E895D2FBC70F11E9A775825E9397B0B89FE00FDD96BA8158F8A542Aid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_L_2147827321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.L"
        threat_id = "2147827321"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>891176DC3A1523F997D84069748364BD68505DA42153B1D1BF784AFB9DADBE51</p>" wide //weight: 1
        $x_1_2 = {38 39 31 31 37 36 44 43 33 41 31 35 32 33 46 39 39 37 44 38 34 30 36 39 37 34 38 33 36 34 42 44 36 38 35 30 35 44 41 34 32 31 35 33 42 31 44 31 42 46 37 38 34 41 46 42 39 44 41 44 42 45 35 31 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid891176DC3A1523F997D84069748364BD68505DA42153B1D1BF784AFB9DADBE51id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_M_2147827325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.M"
        threat_id = "2147827325"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>D5D9827F7186A50EABC1FBFD3DE8101792F187C584DA9D3D9DEAADBE23DCB16E</p>" wide //weight: 1
        $x_1_2 = {44 35 44 39 38 32 37 46 37 31 38 36 41 35 30 45 41 42 43 31 46 42 46 44 33 44 45 38 31 30 31 37 39 32 46 31 38 37 43 35 38 34 44 41 39 44 33 44 39 44 45 41 41 44 42 45 32 33 44 43 42 31 36 45 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidD5D9827F7186A50EABC1FBFD3DE8101792F187C584DA9D3D9DEAADBE23DCB16Eid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_N_2147827329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.N"
        threat_id = "2147827329"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>070AD41653BADCD8CFE9EEBDC363107BA87DB5C3E56F2EE8A261F8B70EF61F0A</p>" wide //weight: 1
        $x_1_2 = {30 37 30 41 44 34 31 36 35 33 42 41 44 43 44 38 43 46 45 39 45 45 42 44 43 33 36 33 31 30 37 42 41 38 37 44 42 35 43 33 45 35 36 46 32 45 45 38 41 32 36 31 46 38 42 37 30 45 46 36 31 46 30 41 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid070AD41653BADCD8CFE9EEBDC363107BA87DB5C3E56F2EE8A261F8B70EF61F0Aid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_O_2147827333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.O"
        threat_id = "2147827333"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>885800AB83209EB47A9FC6C667224DB9B0DC02EEE1105229AC22E4F1D6A2125E</p>" wide //weight: 1
        $x_1_2 = {38 38 35 38 30 30 41 42 38 33 32 30 39 45 42 34 37 41 39 46 43 36 43 36 36 37 32 32 34 44 42 39 42 30 44 43 30 32 45 45 45 31 31 30 35 32 32 39 41 43 32 32 45 34 46 31 44 36 41 32 31 32 35 45 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid885800AB83209EB47A9FC6C667224DB9B0DC02EEE1105229AC22E4F1D6A2125Eid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_P_2147827981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.P"
        threat_id = "2147827981"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>AB4FEBA9CABBD9E98CBF6745592B0E1C34F91492FD8D02AD802F92C893F49B20</p>" wide //weight: 1
        $x_1_2 = {41 42 34 46 45 42 41 39 43 41 42 42 44 39 45 39 38 43 42 46 36 37 34 35 35 39 32 42 30 45 31 43 33 34 46 39 31 34 39 32 46 44 38 44 30 32 41 44 38 30 32 46 39 32 43 38 39 33 46 34 39 42 32 30 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidAB4FEBA9CABBD9E98CBF6745592B0E1C34F91492FD8D02AD802F92C893F49B20id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_Q_2147829192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.Q"
        threat_id = "2147829192"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>ABF25D000C5375AA30743D32E30C60B603048117B99CFF0C8ECC1EB53F9C7958</p>" wide //weight: 1
        $x_1_2 = {41 42 46 32 35 44 30 30 30 43 35 33 37 35 41 41 33 30 37 34 33 44 33 32 45 33 30 43 36 30 42 36 30 33 30 34 38 31 31 37 42 39 39 43 46 46 30 43 38 45 43 43 31 45 42 35 33 46 39 43 37 39 35 38 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidABF25D000C5375AA30743D32E30C60B603048117B99CFF0C8ECC1EB53F9C7958id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_R_2147829306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.R"
        threat_id = "2147829306"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>4F152368FB89FA84E292D30C007046511FE12FE35D4C0AEA74A15FB0E5A90848</p>" wide //weight: 1
        $x_1_2 = {34 46 31 35 32 33 36 38 46 42 38 39 46 41 38 34 45 32 39 32 44 33 30 43 30 30 37 30 34 36 35 31 31 46 45 31 32 46 45 33 35 44 34 43 30 41 45 41 37 34 41 31 35 46 42 30 45 35 41 39 30 38 34 38 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid4F152368FB89FA84E292D30C007046511FE12FE35D4C0AEA74A15FB0E5A90848id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_S_2147829310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.S"
        threat_id = "2147829310"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>671263E7BC06103C77146A5ABB802A63F53A42B4C4766329A5F04D2660C99A36</p>" wide //weight: 1
        $x_1_2 = {36 37 31 32 36 33 45 37 42 43 30 36 31 30 33 43 37 37 31 34 36 41 35 41 42 42 38 30 32 41 36 33 46 35 33 41 34 32 42 34 43 34 37 36 36 33 32 39 41 35 46 30 34 44 32 36 36 30 43 39 39 41 33 36 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid671263E7BC06103C77146A5ABB802A63F53A42B4C4766329A5F04D2660C99A36id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_T_2147829452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.T"
        threat_id = "2147829452"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>A2DCDE8AAC5AB15F552621CF24A44A708EDFD0C89E22AE77087FA1E2F4FA057A</p>" wide //weight: 1
        $x_1_2 = {41 32 44 43 44 45 38 41 41 43 35 41 42 31 35 46 35 35 32 36 32 31 43 46 32 34 41 34 34 41 37 30 38 45 44 46 44 30 43 38 39 45 32 32 41 45 37 37 30 38 37 46 41 31 45 32 46 34 46 41 30 35 37 41 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidA2DCDE8AAC5AB15F552621CF24A44A708EDFD0C89E22AE77087FA1E2F4FA057Aid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_U_2147829456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.U"
        threat_id = "2147829456"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>AEBC11812927786A9A05D3BC5849359BA58601586F4FF356E0CE7EDE218DA002</p>" wide //weight: 1
        $x_1_2 = {41 45 42 43 31 31 38 31 32 39 32 37 37 38 36 41 39 41 30 35 44 33 42 43 35 38 34 39 33 35 39 42 41 35 38 36 30 31 35 38 36 46 34 46 46 33 35 36 45 30 43 45 37 45 44 45 32 31 38 44 41 30 30 32 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidAEBC11812927786A9A05D3BC5849359BA58601586F4FF356E0CE7EDE218DA002id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_V_2147830248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.V"
        threat_id = "2147830248"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>E906C710E15BCB045AD06338132ADB4591BFCE0107B66CFA64DD26A24931DE60</p>" wide //weight: 1
        $x_1_2 = {45 39 30 36 43 37 31 30 45 31 35 42 43 42 30 34 35 41 44 30 36 33 33 38 31 33 32 41 44 42 34 35 39 31 42 46 43 45 30 31 30 37 42 36 36 43 46 41 36 34 44 44 32 36 41 32 34 39 33 31 44 45 36 30 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidE906C710E15BCB045AD06338132ADB4591BFCE0107B66CFA64DD26A24931DE60id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_W_2147830350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.W"
        threat_id = "2147830350"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>88245BB83F14FD2EC517E3B09E56F968C1C4CD8162D5E534AD09438712E8D85D</p>" wide //weight: 1
        $x_1_2 = {38 38 32 34 35 42 42 38 33 46 31 34 46 44 32 45 43 35 31 37 45 33 42 30 39 45 35 36 46 39 36 38 43 31 43 34 43 44 38 31 36 32 44 35 45 35 33 34 41 44 30 39 34 33 38 37 31 32 45 38 44 38 35 44 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid88245BB83F14FD2EC517E3B09E56F968C1C4CD8162D5E534AD09438712E8D85Did" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_X_2147830546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.X"
        threat_id = "2147830546"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>D3404141459BC7206CC4AFEC16A3403F262C0937A732C12644E7CA97F0615201</p>" wide //weight: 1
        $x_1_2 = {44 33 34 30 34 31 34 31 34 35 39 42 43 37 32 30 36 43 43 34 41 46 45 43 31 36 41 33 34 30 33 46 32 36 32 43 30 39 33 37 41 37 33 32 43 31 32 36 34 34 45 37 43 41 39 37 46 30 36 31 35 32 30 31 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidD3404141459BC7206CC4AFEC16A3403F262C0937A732C12644E7CA97F0615201id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_Y_2147831037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.Y"
        threat_id = "2147831037"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>E4769B1DEF6167C65799E7FA724004E97F6AC5F7C65F9DFF05F6674C5BAA3E42</p>" wide //weight: 1
        $x_1_2 = {45 34 37 36 39 42 31 44 45 46 36 31 36 37 43 36 35 37 39 39 45 37 46 41 37 32 34 30 30 34 45 39 37 46 36 41 43 35 46 37 43 36 35 46 39 44 46 46 30 35 46 36 36 37 34 43 35 42 41 41 33 45 34 32 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidE4769B1DEF6167C65799E7FA724004E97F6AC5F7C65F9DFF05F6674C5BAA3E42id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_Z_2147831041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.Z"
        threat_id = "2147831041"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>C135F524E4C75FA00B5620F4286FFE7906E459673A64800EF20D944863946E1F</p>" wide //weight: 1
        $x_1_2 = {43 31 33 35 46 35 32 34 45 34 43 37 35 46 41 30 30 42 35 36 32 30 46 34 32 38 36 46 46 45 37 39 30 36 45 34 35 39 36 37 33 41 36 34 38 30 30 45 46 32 30 44 39 34 34 38 36 33 39 34 36 45 31 46 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidC135F524E4C75FA00B5620F4286FFE7906E459673A64800EF20D944863946E1Fid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_AA_2147831045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.AA"
        threat_id = "2147831045"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>007A21A27C39CC64D9AB066A9A71B7B0BE575EE9D287189235BB1F376438150B</p>" wide //weight: 1
        $x_1_2 = {30 30 37 41 32 31 41 32 37 43 33 39 43 43 36 34 44 39 41 42 30 36 36 41 39 41 37 31 42 37 42 30 42 45 35 37 35 45 45 39 44 32 38 37 31 38 39 32 33 35 42 42 31 46 33 37 36 34 33 38 31 35 30 42 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid007A21A27C39CC64D9AB066A9A71B7B0BE575EE9D287189235BB1F376438150Bid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_AB_2147831049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.AB"
        threat_id = "2147831049"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>0EDC46A1C7F449FE1B056633F33A665E070968FE708845B9CC7F0EADCC49921D</p>" wide //weight: 1
        $x_1_2 = {30 45 44 43 34 36 41 31 43 37 46 34 34 39 46 45 31 42 30 35 36 36 33 33 46 33 33 41 36 36 35 45 30 37 30 39 36 38 46 45 37 30 38 38 34 35 42 39 43 43 37 46 30 45 41 44 43 43 34 39 39 32 31 44 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid0EDC46A1C7F449FE1B056633F33A665E070968FE708845B9CC7F0EADCC49921Did" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_AC_2147831053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.AC"
        threat_id = "2147831053"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>899D28D0C43BBF7FE3E4FE5B0CB80914BE4ADA8780A04AFCF6249A95ABA10170</p>" wide //weight: 1
        $x_1_2 = {38 39 39 44 32 38 44 30 43 34 33 42 42 46 37 46 45 33 45 34 46 45 35 42 30 43 42 38 30 39 31 34 42 45 34 41 44 41 38 37 38 30 41 30 34 41 46 43 46 36 32 34 39 41 39 35 41 42 41 31 30 31 37 30 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid899D28D0C43BBF7FE3E4FE5B0CB80914BE4ADA8780A04AFCF6249A95ABA10170id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_AD_2147831057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.AD"
        threat_id = "2147831057"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>3488458145EB62D7D3947E3811234F4663D9B5AEEF6584AB08A2099A7F946664</p>" wide //weight: 1
        $x_1_2 = {33 34 38 38 34 35 38 31 34 35 45 42 36 32 44 37 44 33 39 34 37 45 33 38 31 31 32 33 34 46 34 36 36 33 44 39 42 35 41 45 45 46 36 35 38 34 41 42 30 38 41 32 30 39 39 41 37 46 39 34 36 36 36 34 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid3488458145EB62D7D3947E3811234F4663D9B5AEEF6584AB08A2099A7F946664id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_AE_2147831061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.AE"
        threat_id = "2147831061"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>78DB22E30C48561EF8B63AFF7702B237A4797017EBC3630853CF6F11F8706A3A</p>" wide //weight: 1
        $x_1_2 = {37 38 44 42 32 32 45 33 30 43 34 38 35 36 31 45 46 38 42 36 33 41 46 46 37 37 30 32 42 32 33 37 41 34 37 39 37 30 31 37 45 42 43 33 36 33 30 38 35 33 43 46 36 46 31 31 46 38 37 30 36 41 33 41 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid78DB22E30C48561EF8B63AFF7702B237A4797017EBC3630853CF6F11F8706A3Aid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_AF_2147831065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.AF"
        threat_id = "2147831065"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>37790E2D198DFD20C9D2887D4EF7C3E2951BB84248D192689B64DCCA3C8BD808</p>" wide //weight: 1
        $x_1_2 = {33 37 37 39 30 45 32 44 31 39 38 44 46 44 32 30 43 39 44 32 38 38 37 44 34 45 46 37 43 33 45 32 39 35 31 42 42 38 34 32 34 38 44 31 39 32 36 38 39 42 36 34 44 43 43 41 33 43 38 42 44 38 30 38 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid37790E2D198DFD20C9D2887D4EF7C3E2951BB84248D192689B64DCCA3C8BD808id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_AG_2147832087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.AG"
        threat_id = "2147832087"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>1F2F83AA634455DE2FF21DE1CFBF3D5963E666FCFDDA18D3071D2B5F27012F7E</p>" wide //weight: 1
        $x_1_2 = {31 46 32 46 38 33 41 41 36 33 34 34 35 35 44 45 32 46 46 32 31 44 45 31 43 46 42 46 33 44 35 39 36 33 45 36 36 36 46 43 46 44 44 41 31 38 44 33 30 37 31 44 32 42 35 46 32 37 30 31 32 46 37 45 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid1F2F83AA634455DE2FF21DE1CFBF3D5963E666FCFDDA18D3071D2B5F27012F7Eid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_AH_2147832477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.AH"
        threat_id = "2147832477"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>92392B907E97561DEDB20D1005D20910334AD3E72B8E1AB003BB1F4A53FFB072</p>" wide //weight: 1
        $x_1_2 = {39 32 33 39 32 42 39 30 37 45 39 37 35 36 31 44 45 44 42 32 30 44 31 30 30 35 44 32 30 39 31 30 33 33 34 41 44 33 45 37 32 42 38 45 31 41 42 30 30 33 42 42 31 46 34 41 35 33 46 46 42 30 37 32 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid92392B907E97561DEDB20D1005D20910334AD3E72B8E1AB003BB1F4A53FFB072id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_AI_2147833375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.AI"
        threat_id = "2147833375"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>C1BDC6949510F7879F0782A3286392BFCC124E3393BD66592D84EEF135421D47</p>" wide //weight: 1
        $x_1_2 = {43 31 42 44 43 36 39 34 39 35 31 30 46 37 38 37 39 46 30 37 38 32 41 33 32 38 36 33 39 32 42 46 43 43 31 32 34 45 33 33 39 33 42 44 36 36 35 39 32 44 38 34 45 45 46 31 33 35 34 32 31 44 34 37 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidC1BDC6949510F7879F0782A3286392BFCC124E3393BD66592D84EEF135421D47id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_AJ_2147835206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.AJ"
        threat_id = "2147835206"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>047C485EF868D556627D71E891C2D112BD2594912B1DFE1C1AE0E1405D8A3364</p>" wide //weight: 1
        $x_1_2 = {30 34 37 43 34 38 35 45 46 38 36 38 44 35 35 36 36 32 37 44 37 31 45 38 39 31 43 32 44 31 31 32 42 44 32 35 39 34 39 31 32 42 31 44 46 45 31 43 31 41 45 30 45 31 34 30 35 44 38 41 33 33 36 34 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid047C485EF868D556627D71E891C2D112BD2594912B1DFE1C1AE0E1405D8A3364id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_AK_2147841749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.AK"
        threat_id = "2147841749"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>0A07A62A3C798ED0A5225E2F56EA6EEECE5B97BBD86EA7A68A8F6A43FB5C9502</p>" wide //weight: 1
        $x_1_2 = {30 41 30 37 41 36 32 41 33 43 37 39 38 45 44 30 41 35 32 32 35 45 32 46 35 36 45 41 36 45 45 45 43 45 35 42 39 37 42 42 44 38 36 45 41 37 41 36 38 41 38 46 36 41 34 33 46 42 35 43 39 35 30 32 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid0A07A62A3C798ED0A5225E2F56EA6EEECE5B97BBD86EA7A68A8F6A43FB5C9502id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_AL_2147841753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.AL"
        threat_id = "2147841753"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>D6C324719AD0AA50A54E4F8DED8E8220D8698DD67B218B5429466C40E7F72657</p>" wide //weight: 1
        $x_1_2 = {44 36 43 33 32 34 37 31 39 41 44 30 41 41 35 30 41 35 34 45 34 46 38 44 45 44 38 45 38 32 32 30 44 38 36 39 38 44 44 36 37 42 32 31 38 42 35 34 32 39 34 36 36 43 34 30 45 37 46 37 32 36 35 37 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidD6C324719AD0AA50A54E4F8DED8E8220D8698DD67B218B5429466C40E7F72657id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_AM_2147841757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.AM"
        threat_id = "2147841757"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>AB33BC51AFAC64D98226826E70B483593C81CB22E6A3B504F7A75348C38C862F</p>" wide //weight: 1
        $x_1_2 = {41 42 33 33 42 43 35 31 41 46 41 43 36 34 44 39 38 32 32 36 38 32 36 45 37 30 42 34 38 33 35 39 33 43 38 31 43 42 32 32 45 36 41 33 42 35 30 34 46 37 41 37 35 33 34 38 43 33 38 43 38 36 32 46 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidAB33BC51AFAC64D98226826E70B483593C81CB22E6A3B504F7A75348C38C862Fid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_AN_2147841970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.AN"
        threat_id = "2147841970"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>70A6C767835311185DB9A53970FE18D30A4F876B11E470BE99A4B399C712316B</p>" wide //weight: 1
        $x_1_2 = {37 30 41 36 43 37 36 37 38 33 35 33 31 31 31 38 35 44 42 39 41 35 33 39 37 30 46 45 31 38 44 33 30 41 34 46 38 37 36 42 31 31 45 34 37 30 42 45 39 39 41 34 42 33 39 39 43 37 31 32 33 31 36 42 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid70A6C767835311185DB9A53970FE18D30A4F876B11E470BE99A4B399C712316Bid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_AO_2147841974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.AO"
        threat_id = "2147841974"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>4A7F41CC6A5B87AF99450066F313C224D4E0E5501414670A8C5B802403E6292F</p>" wide //weight: 1
        $x_1_2 = {34 41 37 46 34 31 43 43 36 41 35 42 38 37 41 46 39 39 34 35 30 30 36 36 46 33 31 33 43 32 32 34 44 34 45 30 45 35 35 30 31 34 31 34 36 37 30 41 38 43 35 42 38 30 32 34 30 33 45 36 32 39 32 46 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid4A7F41CC6A5B87AF99450066F313C224D4E0E5501414670A8C5B802403E6292Fid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_AP_2147844845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.AP"
        threat_id = "2147844845"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>EBBB598994F84A48470423157C23FD9E76CD7AA05BE5602BDB50E13CA82F7838</p>" wide //weight: 1
        $x_1_2 = {45 42 42 42 35 39 38 39 39 34 46 38 34 41 34 38 34 37 30 34 32 33 31 35 37 43 32 33 46 44 39 45 37 36 43 44 37 41 41 30 35 42 45 35 36 30 32 42 44 42 35 30 45 31 33 43 41 38 32 46 37 38 33 38 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidEBBB598994F84A48470423157C23FD9E76CD7AA05BE5602BDB50E13CA82F7838id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_AQ_2147844849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.AQ"
        threat_id = "2147844849"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>A746E398A5BC9AD9F281F5D10CF861546092D0F2107F12EA9F107EFB7D21CA41</p>" wide //weight: 1
        $x_1_2 = {41 37 34 36 45 33 39 38 41 35 42 43 39 41 44 39 46 32 38 31 46 35 44 31 30 43 46 38 36 31 35 34 36 30 39 32 44 30 46 32 31 30 37 46 31 32 45 41 39 46 31 30 37 45 46 42 37 44 32 31 43 41 34 31 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidA746E398A5BC9AD9F281F5D10CF861546092D0F2107F12EA9F107EFB7D21CA41id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_AR_2147844853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.AR"
        threat_id = "2147844853"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>A4B3B0845DA242A64BF17E0DB4278EDF85855739667D3E2AE8B89D5439015F07</p>" wide //weight: 1
        $x_1_2 = {41 34 42 33 42 30 38 34 35 44 41 32 34 32 41 36 34 42 46 31 37 45 30 44 42 34 32 37 38 45 44 46 38 35 38 35 35 37 33 39 36 36 37 44 33 45 32 41 45 38 42 38 39 44 35 34 33 39 30 31 35 46 30 37 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidA4B3B0845DA242A64BF17E0DB4278EDF85855739667D3E2AE8B89D5439015F07id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_AS_2147844857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.AS"
        threat_id = "2147844857"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>2065307A4522EBFA9C862DB7C20033B71D882EBA11D0E14208721BD1EC64551C</p>" wide //weight: 1
        $x_1_2 = {32 30 36 35 33 30 37 41 34 35 32 32 45 42 46 41 39 43 38 36 32 44 42 37 43 32 30 30 33 33 42 37 31 44 38 38 32 45 42 41 31 31 44 30 45 31 34 32 30 38 37 32 31 42 44 31 45 43 36 34 35 35 31 43 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid2065307A4522EBFA9C862DB7C20033B71D882EBA11D0E14208721BD1EC64551Cid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_AT_2147844861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.AT"
        threat_id = "2147844861"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>9FE0CA434933D63AA72E6037F87AF3E1FBBE698346268CCDE6CCC30E037EC602</p>" wide //weight: 1
        $x_1_2 = {39 46 45 30 43 41 34 33 34 39 33 33 44 36 33 41 41 37 32 45 36 30 33 37 46 38 37 41 46 33 45 31 46 42 42 45 36 39 38 33 34 36 32 36 38 43 43 44 45 36 43 43 43 33 30 45 30 33 37 45 43 36 30 32 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid9FE0CA434933D63AA72E6037F87AF3E1FBBE698346268CCDE6CCC30E037EC602id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_AU_2147845181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.AU"
        threat_id = "2147845181"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>E58D2154A7CAA8172E8AD15159AF1B1B3322E50A35D5821A29BC48D25143D33F</p>" wide //weight: 1
        $x_1_2 = {45 35 38 44 32 31 35 34 41 37 43 41 41 38 31 37 32 45 38 41 44 31 35 31 35 39 41 46 31 42 31 42 33 33 32 32 45 35 30 41 33 35 44 35 38 32 31 41 32 39 42 43 34 38 44 32 35 31 34 33 44 33 33 46 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidE58D2154A7CAA8172E8AD15159AF1B1B3322E50A35D5821A29BC48D25143D33Fid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_AV_2147845185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.AV"
        threat_id = "2147845185"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>A4D33CD121274DF98FB5C256E44562ED61E1BE5333BCC9D7605960499E3C6F1B</p>" wide //weight: 1
        $x_1_2 = {41 34 44 33 33 43 44 31 32 31 32 37 34 44 46 39 38 46 42 35 43 32 35 36 45 34 34 35 36 32 45 44 36 31 45 31 42 45 35 33 33 33 42 43 43 39 44 37 36 30 35 39 36 30 34 39 39 45 33 43 36 46 31 42 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidA4D33CD121274DF98FB5C256E44562ED61E1BE5333BCC9D7605960499E3C6F1Bid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_AW_2147845189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.AW"
        threat_id = "2147845189"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>A5852A300E402AD8AA973E1147D024FFE7DCF34BCC203C7B9DFB8560A3B10361</p>" wide //weight: 1
        $x_1_2 = {41 35 38 35 32 41 33 30 30 45 34 30 32 41 44 38 41 41 39 37 33 45 31 31 34 37 44 30 32 34 46 46 45 37 44 43 46 33 34 42 43 43 32 30 33 43 37 42 39 44 46 42 38 35 36 30 41 33 42 31 30 33 36 31 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidA5852A300E402AD8AA973E1147D024FFE7DCF34BCC203C7B9DFB8560A3B10361id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_AX_2147845915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.AX"
        threat_id = "2147845915"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>7367B422CD7498D5F2AAF33F58F67A332F8520CF0279A5FBB4611E0121AE421A</p>" wide //weight: 1
        $x_1_2 = {37 33 36 37 42 34 32 32 43 44 37 34 39 38 44 35 46 32 41 41 46 33 33 46 35 38 46 36 37 41 33 33 32 46 38 35 32 30 43 46 30 32 37 39 41 35 46 42 42 34 36 31 31 45 30 31 32 31 41 45 34 32 31 41 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid7367B422CD7498D5F2AAF33F58F67A332F8520CF0279A5FBB4611E0121AE421Aid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_AY_2147846949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.AY"
        threat_id = "2147846949"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>E3213A199CDA7618AC22486EFECBD9F8E049AC36094D56AC1BFBE67EB9C3CF23</p>" wide //weight: 1
        $x_1_2 = {45 33 32 31 33 41 31 39 39 43 44 41 37 36 31 38 41 43 32 32 34 38 36 45 46 45 43 42 44 39 46 38 45 30 34 39 41 43 33 36 30 39 34 44 35 36 41 43 31 42 46 42 45 36 37 45 42 39 43 33 43 46 32 33 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidE3213A199CDA7618AC22486EFECBD9F8E049AC36094D56AC1BFBE67EB9C3CF23id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_AZ_2147846962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.AZ"
        threat_id = "2147846962"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>0ACA3AD2BD96541F66616CC088342107CF9F28997C1F697E50864393B8B82913</p>" wide //weight: 1
        $x_1_2 = {30 41 43 41 33 41 44 32 42 44 39 36 35 34 31 46 36 36 36 31 36 43 43 30 38 38 33 34 32 31 30 37 43 46 39 46 32 38 39 39 37 43 31 46 36 39 37 45 35 30 38 36 34 33 39 33 42 38 42 38 32 39 31 33 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid0ACA3AD2BD96541F66616CC088342107CF9F28997C1F697E50864393B8B82913id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_BA_2147847186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.BA"
        threat_id = "2147847186"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>6B76005FF5B3739B44CE38F0F4452C0DF2433F7B44B522DCD17B6151A6617744</p>" wide //weight: 1
        $x_1_2 = {36 42 37 36 30 30 35 46 46 35 42 33 37 33 39 42 34 34 43 45 33 38 46 30 46 34 34 35 32 43 30 44 46 32 34 33 33 46 37 42 34 34 42 35 32 32 44 43 44 31 37 42 36 31 35 31 41 36 36 31 37 37 34 34 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid6B76005FF5B3739B44CE38F0F4452C0DF2433F7B44B522DCD17B6151A6617744id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_BB_2147847679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.BB"
        threat_id = "2147847679"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>71FE82F1B76CAFD9A75E71B42CBA46824DBF0F1F3506ABF8EE0CB7BF40F73D4A</p>" wide //weight: 1
        $x_1_2 = {37 31 46 45 38 32 46 31 42 37 36 43 41 46 44 39 41 37 35 45 37 31 42 34 32 43 42 41 34 36 38 32 34 44 42 46 30 46 31 46 33 35 30 36 41 42 46 38 45 45 30 43 42 37 42 46 34 30 46 37 33 44 34 41 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid71FE82F1B76CAFD9A75E71B42CBA46824DBF0F1F3506ABF8EE0CB7BF40F73D4Aid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_BC_2147847683_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.BC"
        threat_id = "2147847683"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>2FE7DA695F96154B1EC5AE05E9BBBACDF976FC5FFD9D1D4FDC34B79DBA02A432</p>" wide //weight: 1
        $x_1_2 = {32 46 45 37 44 41 36 39 35 46 39 36 31 35 34 42 31 45 43 35 41 45 30 35 45 39 42 42 42 41 43 44 46 39 37 36 46 43 35 46 46 44 39 44 31 44 34 46 44 43 33 34 42 37 39 44 42 41 30 32 41 34 33 32 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid2FE7DA695F96154B1EC5AE05E9BBBACDF976FC5FFD9D1D4FDC34B79DBA02A432id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_BD_2147849197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.BD"
        threat_id = "2147849197"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>3F2A79CEDC9328540DF8E75682A36DA326E612ABBF9CBA6FC510EAF53D2EE608</p>" wide //weight: 1
        $x_1_2 = {33 46 32 41 37 39 43 45 44 43 39 33 32 38 35 34 30 44 46 38 45 37 35 36 38 32 41 33 36 44 41 33 32 36 45 36 31 32 41 42 42 46 39 43 42 41 36 46 43 35 31 30 45 41 46 35 33 44 32 45 45 36 30 38 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid3F2A79CEDC9328540DF8E75682A36DA326E612ABBF9CBA6FC510EAF53D2EE608id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_BE_2147849201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.BE"
        threat_id = "2147849201"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>8F0E308CB4D9F1F3F80EC93A4C566B8CFCCAB0967F0637C00ED3079C37235652</p>" wide //weight: 1
        $x_1_2 = {38 46 30 45 33 30 38 43 42 34 44 39 46 31 46 33 46 38 30 45 43 39 33 41 34 43 35 36 36 42 38 43 46 43 43 41 42 30 39 36 37 46 30 36 33 37 43 30 30 45 44 33 30 37 39 43 33 37 32 33 35 36 35 32 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid8F0E308CB4D9F1F3F80EC93A4C566B8CFCCAB0967F0637C00ED3079C37235652id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_BF_2147849660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.BF"
        threat_id = "2147849660"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>DBA5908245E3067FDA9B0C0D6FEEADC3D3C965A29AC340CA14D539924700DC53</p>" wide //weight: 1
        $x_1_2 = {44 42 41 35 39 30 38 32 34 35 45 33 30 36 37 46 44 41 39 42 30 43 30 44 36 46 45 45 41 44 43 33 44 33 43 39 36 35 41 32 39 41 43 33 34 30 43 41 31 34 44 35 33 39 39 32 34 37 30 30 44 43 35 33 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidDBA5908245E3067FDA9B0C0D6FEEADC3D3C965A29AC340CA14D539924700DC53id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_BG_2147849870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.BG"
        threat_id = "2147849870"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>E9CD65687463F67F64937E961DD723DC82C79CB548375AAE8AA4A0698D356C5E</p>" wide //weight: 1
        $x_1_2 = {45 39 43 44 36 35 36 38 37 34 36 33 46 36 37 46 36 34 39 33 37 45 39 36 31 44 44 37 32 33 44 43 38 32 43 37 39 43 42 35 34 38 33 37 35 41 41 45 38 41 41 34 41 30 36 39 38 44 33 35 36 43 35 45 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidE9CD65687463F67F64937E961DD723DC82C79CB548375AAE8AA4A0698D356C5Eid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_BH_2147849874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.BH"
        threat_id = "2147849874"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>7043099A06D401A1F441F2FAD54FC2072A52FD6D250893B73C372448FAFDCE08</p>" wide //weight: 1
        $x_1_2 = {37 30 34 33 30 39 39 41 30 36 44 34 30 31 41 31 46 34 34 31 46 32 46 41 44 35 34 46 43 32 30 37 32 41 35 32 46 44 36 44 32 35 30 38 39 33 42 37 33 43 33 37 32 34 34 38 46 41 46 44 43 45 30 38 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid7043099A06D401A1F441F2FAD54FC2072A52FD6D250893B73C372448FAFDCE08id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_BI_2147850062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.BI"
        threat_id = "2147850062"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>77A904360EA7D74268E7A4F316865F1703D2D7A6AF28C9ECFACED69CD09C8610</p>" wide //weight: 1
        $x_1_2 = {37 37 41 39 30 34 33 36 30 45 41 37 44 37 34 32 36 38 45 37 41 34 46 33 31 36 38 36 35 46 31 37 30 33 44 32 44 37 41 36 41 46 32 38 43 39 45 43 46 41 43 45 44 36 39 43 44 30 39 43 38 36 31 30 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid77A904360EA7D74268E7A4F316865F1703D2D7A6AF28C9ECFACED69CD09C8610id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_BJ_2147850066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.BJ"
        threat_id = "2147850066"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>84032B92D37C888FD3572909059BD6FA77612DD4FE62B4587A48DE33322AB67E</p>" wide //weight: 1
        $x_1_2 = {38 34 30 33 32 42 39 32 44 33 37 43 38 38 38 46 44 33 35 37 32 39 30 39 30 35 39 42 44 36 46 41 37 37 36 31 32 44 44 34 46 45 36 32 42 34 35 38 37 41 34 38 44 45 33 33 33 32 32 41 42 36 37 45 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid84032B92D37C888FD3572909059BD6FA77612DD4FE62B4587A48DE33322AB67Eid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_BK_2147850837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.BK"
        threat_id = "2147850837"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>8B7C5C04B7431200645C9E190BB1EFABBFB3826810AAFCFF01ACF9B4080E5502</p>" wide //weight: 1
        $x_1_2 = {38 42 37 43 35 43 30 34 42 37 34 33 31 32 30 30 36 34 35 43 39 45 31 39 30 42 42 31 45 46 41 42 42 46 42 33 38 32 36 38 31 30 41 41 46 43 46 46 30 31 41 43 46 39 42 34 30 38 30 45 35 35 30 32 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid8B7C5C04B7431200645C9E190BB1EFABBFB3826810AAFCFF01ACF9B4080E5502id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_BL_2147851105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.BL"
        threat_id = "2147851105"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>BC9132FAE386CD10790AB21400CF248D56DFEC29E5403C144ACCA8D426D68B33</p>" wide //weight: 1
        $x_1_2 = {42 43 39 31 33 32 46 41 45 33 38 36 43 44 31 30 37 39 30 41 42 32 31 34 30 30 43 46 32 34 38 44 35 36 44 46 45 43 32 39 45 35 34 30 33 43 31 34 34 41 43 43 41 38 44 34 32 36 44 36 38 42 33 33 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidBC9132FAE386CD10790AB21400CF248D56DFEC29E5403C144ACCA8D426D68B33id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_BM_2147851926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.BM"
        threat_id = "2147851926"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>126E30C4CC9DE90F79D1FA90830FDC2069A2E981ED26B6DC148DA8827FB3D63A</p>" wide //weight: 1
        $x_1_2 = {31 32 36 45 33 30 43 34 43 43 39 44 45 39 30 46 37 39 44 31 46 41 39 30 38 33 30 46 44 43 32 30 36 39 41 32 45 39 38 31 45 44 32 36 42 36 44 43 31 34 38 44 41 38 38 32 37 46 42 33 44 36 33 41 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid126E30C4CC9DE90F79D1FA90830FDC2069A2E981ED26B6DC148DA8827FB3D63Aid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_BN_2147852260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.BN"
        threat_id = "2147852260"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>A7B9AD23F5AC4AB5404BFDE1E67CE0797F4FFD1C79D8A539E17406A55D5ED93B</p>" wide //weight: 1
        $x_1_2 = {41 37 42 39 41 44 32 33 46 35 41 43 34 41 42 35 34 30 34 42 46 44 45 31 45 36 37 43 45 30 37 39 37 46 34 46 46 44 31 43 37 39 44 38 41 35 33 39 45 31 37 34 30 36 41 35 35 44 35 45 44 39 33 42 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidA7B9AD23F5AC4AB5404BFDE1E67CE0797F4FFD1C79D8A539E17406A55D5ED93Bid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_BO_2147853058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.BO"
        threat_id = "2147853058"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>78E21CFF7AA85F713C1530AEF2E74E62830BEE77238F4B0A73E5E3251EAD5642</p>" wide //weight: 1
        $x_1_2 = {37 38 45 32 31 43 46 46 37 41 41 38 35 46 37 31 33 43 31 35 33 30 41 45 46 32 45 37 34 45 36 32 38 33 30 42 45 45 37 37 32 33 38 46 34 42 30 41 37 33 45 35 45 33 32 35 31 45 41 44 35 36 34 32 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid78E21CFF7AA85F713C1530AEF2E74E62830BEE77238F4B0A73E5E3251EAD5642id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_BP_2147853062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.BP"
        threat_id = "2147853062"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>81A9E67702D5AB17E1CF43296D6FAE7EB8DE6B2DDD69D58404CB19477CCA6B64</p>" wide //weight: 1
        $x_1_2 = {38 31 41 39 45 36 37 37 30 32 44 35 41 42 31 37 45 31 43 46 34 33 32 39 36 44 36 46 41 45 37 45 42 38 44 45 36 42 32 44 44 44 36 39 44 35 38 34 30 34 43 42 31 39 34 37 37 43 43 41 36 42 36 34 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid81A9E67702D5AB17E1CF43296D6FAE7EB8DE6B2DDD69D58404CB19477CCA6B64id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_BQ_2147853439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.BQ"
        threat_id = "2147853439"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>9096AD7062A4232F5AA31C2F7C4DF0AC1EAD10B78D40A6A3328AD142A42B555E</p>" wide //weight: 1
        $x_1_2 = {39 30 39 36 41 44 37 30 36 32 41 34 32 33 32 46 35 41 41 33 31 43 32 46 37 43 34 44 46 30 41 43 31 45 41 44 31 30 42 37 38 44 34 30 41 36 41 33 33 32 38 41 44 31 34 32 41 34 32 42 35 35 35 45 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid9096AD7062A4232F5AA31C2F7C4DF0AC1EAD10B78D40A6A3328AD142A42B555Eid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_BR_2147853443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.BR"
        threat_id = "2147853443"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>4AE245548F2A225882951FB14E9BF87EE01A0C10AE159B99D1EA62620D91A372</p>" wide //weight: 1
        $x_1_2 = {34 41 45 32 34 35 35 34 38 46 32 41 32 32 35 38 38 32 39 35 31 46 42 31 34 45 39 42 46 38 37 45 45 30 31 41 30 43 31 30 41 45 31 35 39 42 39 39 44 31 45 41 36 32 36 32 30 44 39 31 41 33 37 32 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid4AE245548F2A225882951FB14E9BF87EE01A0C10AE159B99D1EA62620D91A372id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_BS_2147888322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.BS"
        threat_id = "2147888322"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>A5F2F6058F70CE5953DC475EE6AF1F97FC6D487ABEBAE76915075E3A53525B1D</p>" wide //weight: 1
        $x_1_2 = {41 35 46 32 46 36 30 35 38 46 37 30 43 45 35 39 35 33 44 43 34 37 35 45 45 36 41 46 31 46 39 37 46 43 36 44 34 38 37 41 42 45 42 41 45 37 36 39 31 35 30 37 35 45 33 41 35 33 35 32 35 42 31 44 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidA5F2F6058F70CE5953DC475EE6AF1F97FC6D487ABEBAE76915075E3A53525B1Did" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_BT_2147888556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.BT"
        threat_id = "2147888556"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>3C9D49B928FDC3C15F0314217623A71B865909B308576B4B0D10AEA62C98677B</p>" wide //weight: 1
        $x_1_2 = {33 43 39 44 34 39 42 39 32 38 46 44 43 33 43 31 35 46 30 33 31 34 32 31 37 36 32 33 41 37 31 42 38 36 35 39 30 39 42 33 30 38 35 37 36 42 34 42 30 44 31 30 41 45 41 36 32 43 39 38 36 37 37 42 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid3C9D49B928FDC3C15F0314217623A71B865909B308576B4B0D10AEA62C98677Bid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_BU_2147888560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.BU"
        threat_id = "2147888560"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>4F15236BFB89FA84E292D30C007046511FE12FE35D4C0AEA74A15FB0E5A90848</p>" wide //weight: 1
        $x_1_2 = {34 46 31 35 32 33 36 42 46 42 38 39 46 41 38 34 45 32 39 32 44 33 30 43 30 30 37 30 34 36 35 31 31 46 45 31 32 46 45 33 35 44 34 43 30 41 45 41 37 34 41 31 35 46 42 30 45 35 41 39 30 38 34 38 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid4F15236BFB89FA84E292D30C007046511FE12FE35D4C0AEA74A15FB0E5A90848id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_BV_2147888564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.BV"
        threat_id = "2147888564"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>192D52C7C18F3D2693ED2453E64C53EC0CCF0255AB2291F019B65BA84442B313</p>" wide //weight: 1
        $x_1_2 = {31 39 32 44 35 32 43 37 43 31 38 46 33 44 32 36 39 33 45 44 32 34 35 33 45 36 34 43 35 33 45 43 30 43 43 46 30 32 35 35 41 42 32 32 39 31 46 30 31 39 42 36 35 42 41 38 34 34 34 32 42 33 31 33 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid192D52C7C18F3D2693ED2453E64C53EC0CCF0255AB2291F019B65BA84442B313id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_BW_2147888568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.BW"
        threat_id = "2147888568"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>0A6F992E1372DB4F245595424A7436EBB610775D6ADDC4D568ACC2AF5D315221</p>" wide //weight: 1
        $x_1_2 = {30 41 36 46 39 39 32 45 31 33 37 32 44 42 34 46 32 34 35 35 39 35 34 32 34 41 37 34 33 36 45 42 42 36 31 30 37 37 35 44 36 41 44 44 43 34 44 35 36 38 41 43 43 32 41 46 35 44 33 31 35 32 32 31 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid0A6F992E1372DB4F245595424A7436EBB610775D6ADDC4D568ACC2AF5D315221id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_BX_2147888572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.BX"
        threat_id = "2147888572"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>3FA4D7B4989C059F50B12F28313210ADF04EE9DFE6C2F2AD1048048E92BD4D21</p>" wide //weight: 1
        $x_1_2 = {33 46 41 34 44 37 42 34 39 38 39 43 30 35 39 46 35 30 42 31 32 46 32 38 33 31 33 32 31 30 41 44 46 30 34 45 45 39 44 46 45 36 43 32 46 32 41 44 31 30 34 38 30 34 38 45 39 32 42 44 34 44 32 31 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid3FA4D7B4989C059F50B12F28313210ADF04EE9DFE6C2F2AD1048048E92BD4D21id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_BY_2147888744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.BY"
        threat_id = "2147888744"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>9E1DEB410719C2CD0730E914BA2138795230F318A9EFBA6A5B43E722E9F76028</p>" wide //weight: 1
        $x_1_2 = {39 45 31 44 45 42 34 31 30 37 31 39 43 32 43 44 30 37 33 30 45 39 31 34 42 41 32 31 33 38 37 39 35 32 33 30 46 33 31 38 41 39 45 46 42 41 36 41 35 42 34 33 45 37 32 32 45 39 46 37 36 30 32 38 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid9E1DEB410719C2CD0730E914BA2138795230F318A9EFBA6A5B43E722E9F76028id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_BZ_2147888748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.BZ"
        threat_id = "2147888748"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>87F021ADD4DD69217D3D5BB3B42DAB52F362D8ABE2A831CFE381D3C72BB0AC03</p>" wide //weight: 1
        $x_1_2 = {38 37 46 30 32 31 41 44 44 34 44 44 36 39 32 31 37 44 33 44 35 42 42 33 42 34 32 44 41 42 35 32 46 33 36 32 44 38 41 42 45 32 41 38 33 31 43 46 45 33 38 31 44 33 43 37 32 42 42 30 41 43 30 33 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid87F021ADD4DD69217D3D5BB3B42DAB52F362D8ABE2A831CFE381D3C72BB0AC03id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_CA_2147888752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.CA"
        threat_id = "2147888752"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>CFAC328D48B8A1499A1E67423F60E502A22557558CEEDD77A1A3DE59B2144C38</p>" wide //weight: 1
        $x_1_2 = {43 46 41 43 33 32 38 44 34 38 42 38 41 31 34 39 39 41 31 45 36 37 34 32 33 46 36 30 45 35 30 32 41 32 32 35 35 37 35 35 38 43 45 45 44 44 37 37 41 31 41 33 44 45 35 39 42 32 31 34 34 43 33 38 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidCFAC328D48B8A1499A1E67423F60E502A22557558CEEDD77A1A3DE59B2144C38id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_CB_2147888756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.CB"
        threat_id = "2147888756"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>75CD9D0B5D0E632A8850B619193E2DC69E55B5697B174D691C4CC72A88636E48</p>" wide //weight: 1
        $x_1_2 = {37 35 43 44 39 44 30 42 35 44 30 45 36 33 32 41 38 38 35 30 42 36 31 39 31 39 33 45 32 44 43 36 39 45 35 35 42 35 36 39 37 42 31 37 34 44 36 39 31 43 34 43 43 37 32 41 38 38 36 33 36 45 34 38 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid75CD9D0B5D0E632A8850B619193E2DC69E55B5697B174D691C4CC72A88636E48id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_CC_2147888760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.CC"
        threat_id = "2147888760"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>D9A671DF6C004AA4850099AFDBA18DD1193B61A386745CD1DED8DEBBB36E0255</p>" wide //weight: 1
        $x_1_2 = {44 39 41 36 37 31 44 46 36 43 30 30 34 41 41 34 38 35 30 30 39 39 41 46 44 42 41 31 38 44 44 31 31 39 33 42 36 31 41 33 38 36 37 34 35 43 44 31 44 45 44 38 44 45 42 42 42 33 36 45 30 32 35 35 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidD9A671DF6C004AA4850099AFDBA18DD1193B61A386745CD1DED8DEBBB36E0255id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_CD_2147888847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.CD"
        threat_id = "2147888847"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>AA7774431263F51F9043515C84C3186D7D685FEBC5AEA490272C75AE61473114</p>" wide //weight: 1
        $x_1_2 = {41 41 37 37 37 34 34 33 31 32 36 33 46 35 31 46 39 30 34 33 35 31 35 43 38 34 43 33 31 38 36 44 37 44 36 38 35 46 45 42 43 35 41 45 41 34 39 30 32 37 32 43 37 35 41 45 36 31 34 37 33 31 31 34 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidAA7774431263F51F9043515C84C3186D7D685FEBC5AEA490272C75AE61473114id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_CE_2147888851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.CE"
        threat_id = "2147888851"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>274D8D5543770DADEEEE88E2B719C149462BF71AB0394EE5FF7FEBF22569EA64</p>" wide //weight: 1
        $x_1_2 = {32 37 34 44 38 44 35 35 34 33 37 37 30 44 41 44 45 45 45 45 38 38 45 32 42 37 31 39 43 31 34 39 34 36 32 42 46 37 31 41 42 30 33 39 34 45 45 35 46 46 37 46 45 42 46 32 32 35 36 39 45 41 36 34 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid274D8D5543770DADEEEE88E2B719C149462BF71AB0394EE5FF7FEBF22569EA64id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_CF_2147888855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.CF"
        threat_id = "2147888855"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>6B494AC81C1ADFA4AD8DFFB3862F45EDB79703FDC8EE4C86B01956D17024EF5D</p>" wide //weight: 1
        $x_1_2 = {36 42 34 39 34 41 43 38 31 43 31 41 44 46 41 34 41 44 38 44 46 46 42 33 38 36 32 46 34 35 45 44 42 37 39 37 30 33 46 44 43 38 45 45 34 43 38 36 42 30 31 39 35 36 44 31 37 30 32 34 45 46 35 44 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid6B494AC81C1ADFA4AD8DFFB3862F45EDB79703FDC8EE4C86B01956D17024EF5Did" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_CG_2147888859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.CG"
        threat_id = "2147888859"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>839A2C1203F1C5D22579B2F646105A7FE8859A42160D4944543A77A38585FA1F</p>" wide //weight: 1
        $x_1_2 = {38 33 39 41 32 43 31 32 30 33 46 31 43 35 44 32 32 35 37 39 42 32 46 36 34 36 31 30 35 41 37 46 45 38 38 35 39 41 34 32 31 36 30 44 34 39 34 34 35 34 33 41 37 37 41 33 38 35 38 35 46 41 31 46 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid839A2C1203F1C5D22579B2F646105A7FE8859A42160D4944543A77A38585FA1Fid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_CH_2147888863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.CH"
        threat_id = "2147888863"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>30EE99903253BC5AE3D404A58AFE28BA373FE73E258A6537C68D7DA4E44E1368</p>" wide //weight: 1
        $x_1_2 = {33 30 45 45 39 39 39 30 33 32 35 33 42 43 35 41 45 33 44 34 30 34 41 35 38 41 46 45 32 38 42 41 33 37 33 46 45 37 33 45 32 35 38 41 36 35 33 37 43 36 38 44 37 44 41 34 45 34 34 45 31 33 36 38 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid30EE99903253BC5AE3D404A58AFE28BA373FE73E258A6537C68D7DA4E44E1368id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_CI_2147888967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.CI"
        threat_id = "2147888967"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>A1684234F478AF4A32CF9539D997C324D5CEC14F9474A83544ABEFFD133C286F</p>" wide //weight: 1
        $x_1_2 = {41 31 36 38 34 32 33 34 46 34 37 38 41 46 34 41 33 32 43 46 39 35 33 39 44 39 39 37 43 33 32 34 44 35 43 45 43 31 34 46 39 34 37 34 41 38 33 35 34 34 41 42 45 46 46 44 31 33 33 43 32 38 36 46 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidA1684234F478AF4A32CF9539D997C324D5CEC14F9474A83544ABEFFD133C286Fid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_CJ_2147888971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.CJ"
        threat_id = "2147888971"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>2B41B398739E6BECE4E93EAFA0C665E3680C8C7B75C566A44C99C710BB524741</p>" wide //weight: 1
        $x_1_2 = {32 42 34 31 42 33 39 38 37 33 39 45 36 42 45 43 45 34 45 39 33 45 41 46 41 30 43 36 36 35 45 33 36 38 30 43 38 43 37 42 37 35 43 35 36 36 41 34 34 43 39 39 43 37 31 30 42 42 35 32 34 37 34 31 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid2B41B398739E6BECE4E93EAFA0C665E3680C8C7B75C566A44C99C710BB524741id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_CK_2147888975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.CK"
        threat_id = "2147888975"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>B79A7B0B31CF36361487D7CB6E7874132B056528D8AA4146424A7D1ECA72BC44</p>" wide //weight: 1
        $x_1_2 = {42 37 39 41 37 42 30 42 33 31 43 46 33 36 33 36 31 34 38 37 44 37 43 42 36 45 37 38 37 34 31 33 32 42 30 35 36 35 32 38 44 38 41 41 34 31 34 36 34 32 34 41 37 44 31 45 43 41 37 32 42 43 34 34 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidB79A7B0B31CF36361487D7CB6E7874132B056528D8AA4146424A7D1ECA72BC44id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_CL_2147888979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.CL"
        threat_id = "2147888979"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>B2F873769EB6B508EBC2103DDEB7366CEFB7B09AB8314DAD0C43461690726866</p>" wide //weight: 1
        $x_1_2 = {42 32 46 38 37 33 37 36 39 45 42 36 42 35 30 38 45 42 43 32 31 30 33 44 44 45 42 37 33 36 36 43 45 46 42 37 42 30 39 41 42 38 33 31 34 44 41 44 30 43 34 33 34 36 31 36 39 30 37 32 36 38 36 36 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidB2F873769EB6B508EBC2103DDEB7366CEFB7B09AB8314DAD0C43461690726866id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_CM_2147889563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.CM"
        threat_id = "2147889563"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>FDF86CB226833382CE6C1C4A75C9F92BFD7CCA0F2AA6A890E0E67328B653FE20</p>" wide //weight: 1
        $x_1_2 = {46 44 46 38 36 43 42 32 32 36 38 33 33 33 38 32 43 45 36 43 31 43 34 41 37 35 43 39 46 39 32 42 46 44 37 43 43 41 30 46 32 41 41 36 41 38 39 30 45 30 45 36 37 33 32 38 42 36 35 33 46 45 32 30 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidFDF86CB226833382CE6C1C4A75C9F92BFD7CCA0F2AA6A890E0E67328B653FE20id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_CN_2147890158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.CN"
        threat_id = "2147890158"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>777BB9F3522655CC91E0B48E256475A7633E12CCBF8C9EF2910413F9812CF416</p>" wide //weight: 1
        $x_1_2 = {37 37 37 42 42 39 46 33 35 32 32 36 35 35 43 43 39 31 45 30 42 34 38 45 32 35 36 34 37 35 41 37 36 33 33 45 31 32 43 43 42 46 38 43 39 45 46 32 39 31 30 34 31 33 46 39 38 31 32 43 46 34 31 36 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid777BB9F3522655CC91E0B48E256475A7633E12CCBF8C9EF2910413F9812CF416id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_CO_2147890162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.CO"
        threat_id = "2147890162"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>69EB2511167FBE9E68546A93278FD52B7BA8F3F3529D5EEFBD63A513A2E73C3C</p>" wide //weight: 1
        $x_1_2 = {36 39 45 42 32 35 31 31 31 36 37 46 42 45 39 45 36 38 35 34 36 41 39 33 32 37 38 46 44 35 32 42 37 42 41 38 46 33 46 33 35 32 39 44 35 45 45 46 42 44 36 33 41 35 31 33 41 32 45 37 33 43 33 43 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid69EB2511167FBE9E68546A93278FD52B7BA8F3F3529D5EEFBD63A513A2E73C3Cid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_CP_2147890379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.CP"
        threat_id = "2147890379"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>B02838FD4FF823665F855FF713659B87186B9AD90C40F148977DC51352BDB43B</p>" wide //weight: 1
        $x_1_2 = {42 30 32 38 33 38 46 44 34 46 46 38 32 33 36 36 35 46 38 35 35 46 46 37 31 33 36 35 39 42 38 37 31 38 36 42 39 41 44 39 30 43 34 30 46 31 34 38 39 37 37 44 43 35 31 33 35 32 42 44 42 34 33 42 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidB02838FD4FF823665F855FF713659B87186B9AD90C40F148977DC51352BDB43Bid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_CQ_2147890383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.CQ"
        threat_id = "2147890383"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>2FFB95F4FDA76FBAD57BC1984F132304185BDF82DB42152B5E4E81D977B7E518</p>" wide //weight: 1
        $x_1_2 = {32 46 46 42 39 35 46 34 46 44 41 37 36 46 42 41 44 35 37 42 43 31 39 38 34 46 31 33 32 33 30 34 31 38 35 42 44 46 38 32 44 42 34 32 31 35 32 42 35 45 34 45 38 31 44 39 37 37 42 37 45 35 31 38 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid2FFB95F4FDA76FBAD57BC1984F132304185BDF82DB42152B5E4E81D977B7E518id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_CR_2147890572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.CR"
        threat_id = "2147890572"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>BAED7AD40C392D20A6F6857912720B14E69CD01BB1D6E5C0B904EE4BE26E9D13</p>" wide //weight: 1
        $x_1_2 = {42 41 45 44 37 41 44 34 30 43 33 39 32 44 32 30 41 36 46 36 38 35 37 39 31 32 37 32 30 42 31 34 45 36 39 43 44 30 31 42 42 31 44 36 45 35 43 30 42 39 30 34 45 45 34 42 45 32 36 45 39 44 31 33 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidBAED7AD40C392D20A6F6857912720B14E69CD01BB1D6E5C0B904EE4BE26E9D13id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_CS_2147890576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.CS"
        threat_id = "2147890576"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>9F653109E6CFA1890999C1C581500618005F6789D974FB67ED66B98ABF7D0732</p>" wide //weight: 1
        $x_1_2 = {39 46 36 35 33 31 30 39 45 36 43 46 41 31 38 39 30 39 39 39 43 31 43 35 38 31 35 30 30 36 31 38 30 30 35 46 36 37 38 39 44 39 37 34 46 42 36 37 45 44 36 36 42 39 38 41 42 46 37 44 30 37 33 32 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid9F653109E6CFA1890999C1C581500618005F6789D974FB67ED66B98ABF7D0732id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_CT_2147891237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.CT"
        threat_id = "2147891237"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>5FEB774F4CF3A15FC392C3CC90313B964353D2CE9239B878F279BDF80B25CE57</p>" wide //weight: 1
        $x_1_2 = {35 46 45 42 37 37 34 46 34 43 46 33 41 31 35 46 43 33 39 32 43 33 43 43 39 30 33 31 33 42 39 36 34 33 35 33 44 32 43 45 39 32 33 39 42 38 37 38 46 32 37 39 42 44 46 38 30 42 32 35 43 45 35 37 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid5FEB774F4CF3A15FC392C3CC90313B964353D2CE9239B878F279BDF80B25CE57id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_CU_2147891751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.CU"
        threat_id = "2147891751"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>30D1B4FAB9287E9C54969DB3F17A402A0BDFA9BCD45B3B2BDA5688EE879BA770</p>" wide //weight: 1
        $x_1_2 = {33 30 44 31 42 34 46 41 42 39 32 38 37 45 39 43 35 34 39 36 39 44 42 33 46 31 37 41 34 30 32 41 30 42 44 46 41 39 42 43 44 34 35 42 33 42 32 42 44 41 35 36 38 38 45 45 38 37 39 42 41 37 37 30 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid30D1B4FAB9287E9C54969DB3F17A402A0BDFA9BCD45B3B2BDA5688EE879BA770id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_CV_2147891755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.CV"
        threat_id = "2147891755"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>68D93E04CD13FB660DBB8C6672183373C577AF957B78E7FEFFD561EFF7BD110C</p>" wide //weight: 1
        $x_1_2 = {36 38 44 39 33 45 30 34 43 44 31 33 46 42 36 36 30 44 42 42 38 43 36 36 37 32 31 38 33 33 37 33 43 35 37 37 41 46 39 35 37 42 37 38 45 37 46 45 46 46 44 35 36 31 45 46 46 37 42 44 31 31 30 43 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid68D93E04CD13FB660DBB8C6672183373C577AF957B78E7FEFFD561EFF7BD110Cid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_CW_2147891759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.CW"
        threat_id = "2147891759"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>C3CC4E254DEF87B28FD67818F5E446BB23C89B402FACA36B49C0EECFC75AA058</p>" wide //weight: 1
        $x_1_2 = {43 33 43 43 34 45 32 35 34 44 45 46 38 37 42 32 38 46 44 36 37 38 31 38 46 35 45 34 34 36 42 42 32 33 43 38 39 42 34 30 32 46 41 43 41 33 36 42 34 39 43 30 45 45 43 46 43 37 35 41 41 30 35 38 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidC3CC4E254DEF87B28FD67818F5E446BB23C89B402FACA36B49C0EECFC75AA058id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_CX_2147891763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.CX"
        threat_id = "2147891763"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>09B950550CAD95899AC17C0B1384CD55C9BD81396B19EFFE2E80839D641D3221</p>" wide //weight: 1
        $x_1_2 = {30 39 42 39 35 30 35 35 30 43 41 44 39 35 38 39 39 41 43 31 37 43 30 42 31 33 38 34 43 44 35 35 43 39 42 44 38 31 33 39 36 42 31 39 45 46 46 45 32 45 38 30 38 33 39 44 36 34 31 44 33 32 32 31 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid09B950550CAD95899AC17C0B1384CD55C9BD81396B19EFFE2E80839D641D3221id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_CY_2147892603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.CY"
        threat_id = "2147892603"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>0421BD35FA5A5849FB9BEB1595DBBE239DDE19B46B0B8BD73EDD1107C245B46C</p>" wide //weight: 1
        $x_1_2 = {30 34 32 31 42 44 33 35 46 41 35 41 35 38 34 39 46 42 39 42 45 42 31 35 39 35 44 42 42 45 32 33 39 44 44 45 31 39 42 34 36 42 30 42 38 42 44 37 33 45 44 44 31 31 30 37 43 32 34 35 42 34 36 43 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid0421BD35FA5A5849FB9BEB1595DBBE239DDE19B46B0B8BD73EDD1107C245B46Cid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_CZ_2147893022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.CZ"
        threat_id = "2147893022"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>BC3723356CBA89461914C536F047F0E66C20FBC4134FC5E46ABCEFF768D7DC1C</p>" wide //weight: 1
        $x_1_2 = {42 43 33 37 32 33 33 35 36 43 42 41 38 39 34 36 31 39 31 34 43 35 33 36 46 30 34 37 46 30 45 36 36 43 32 30 46 42 43 34 31 33 34 46 43 35 45 34 36 41 42 43 45 46 46 37 36 38 44 37 44 43 31 43 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidBC3723356CBA89461914C536F047F0E66C20FBC4134FC5E46ABCEFF768D7DC1Cid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_DA_2147893026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.DA"
        threat_id = "2147893026"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>D8E29F22B9582F1E7A180A28F0DD90627A1220DD7E90559450B9AAEA64669D0D</p>" wide //weight: 1
        $x_1_2 = {44 38 45 32 39 46 32 32 42 39 35 38 32 46 31 45 37 41 31 38 30 41 32 38 46 30 44 44 39 30 36 32 37 41 31 32 32 30 44 44 37 45 39 30 35 35 39 34 35 30 42 39 41 41 45 41 36 34 36 36 39 44 30 44 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidD8E29F22B9582F1E7A180A28F0DD90627A1220DD7E90559450B9AAEA64669D0Did" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_DB_2147893205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.DB"
        threat_id = "2147893205"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>5B85F0F52F989C42FE18A08351D4B9F50D7A9832DBE4A068346DE35D5CF8F410</p>" wide //weight: 1
        $x_1_2 = {35 42 38 35 46 30 46 35 32 46 39 38 39 43 34 32 46 45 31 38 41 30 38 33 35 31 44 34 42 39 46 35 30 44 37 41 39 38 33 32 44 42 45 34 41 30 36 38 33 34 36 44 45 33 35 44 35 43 46 38 46 34 31 30 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid5B85F0F52F989C42FE18A08351D4B9F50D7A9832DBE4A068346DE35D5CF8F410id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_DC_2147893209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.DC"
        threat_id = "2147893209"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>37737C5A90A32D6417DC12A01CA6A5B8496F7AB1AAAC5CF89AD398B713A1163F</p>" wide //weight: 1
        $x_1_2 = {33 37 37 33 37 43 35 41 39 30 41 33 32 44 36 34 31 37 44 43 31 32 41 30 31 43 41 36 41 35 42 38 34 39 36 46 37 41 42 31 41 41 41 43 35 43 46 38 39 41 44 33 39 38 42 37 31 33 41 31 31 36 33 46 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid37737C5A90A32D6417DC12A01CA6A5B8496F7AB1AAAC5CF89AD398B713A1163Fid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_DD_2147893219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.DD"
        threat_id = "2147893219"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>B761680E23F2EBB5F6887D315EBD05B2D7C365731E093B49ADB059C3DCCAA30C</p>" wide //weight: 1
        $x_1_2 = {42 37 36 31 36 38 30 45 32 33 46 32 45 42 42 35 46 36 38 38 37 44 33 31 35 45 42 44 30 35 42 32 44 37 43 33 36 35 37 33 31 45 30 39 33 42 34 39 41 44 42 30 35 39 43 33 44 43 43 41 41 33 30 43 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidB761680E23F2EBB5F6887D315EBD05B2D7C365731E093B49ADB059C3DCCAA30Cid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_DE_2147893280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.DE"
        threat_id = "2147893280"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>0371CD54F80CBB490ED8E14001F82D6AC9C7FA298E7DB38F6F645028C96AA561</p>" wide //weight: 1
        $x_1_2 = {30 33 37 31 43 44 35 34 46 38 30 43 42 42 34 39 30 45 44 38 45 31 34 30 30 31 46 38 32 44 36 41 43 39 43 37 46 41 32 39 38 45 37 44 42 33 38 46 36 46 36 34 35 30 32 38 43 39 36 41 41 35 36 31 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid0371CD54F80CBB490ED8E14001F82D6AC9C7FA298E7DB38F6F645028C96AA561id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_DF_2147893533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.DF"
        threat_id = "2147893533"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>8F804D66441DF4A210CF43C1B9C074823C7A8D1AE3ACF3215F7EC303717A0E42</p>" wide //weight: 1
        $x_1_2 = {38 46 38 30 34 44 36 36 34 34 31 44 46 34 41 32 31 30 43 46 34 33 43 31 42 39 43 30 37 34 38 32 33 43 37 41 38 44 31 41 45 33 41 43 46 33 32 31 35 46 37 45 43 33 30 33 37 31 37 41 30 45 34 32 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid8F804D66441DF4A210CF43C1B9C074823C7A8D1AE3ACF3215F7EC303717A0E42id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_DG_2147893980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.DG"
        threat_id = "2147893980"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>E21185C273FF3BBAF0522224502D79EAFBC91DAA3F6167DA771E86B49DD0F238</p>" wide //weight: 1
        $x_1_2 = {45 32 31 31 38 35 43 32 37 33 46 46 33 42 42 41 46 30 35 32 32 32 32 34 35 30 32 44 37 39 45 41 46 42 43 39 31 44 41 41 33 46 36 31 36 37 44 41 37 37 31 45 38 36 42 34 39 44 44 30 46 32 33 38 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidE21185C273FF3BBAF0522224502D79EAFBC91DAA3F6167DA771E86B49DD0F238id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_DH_2147893984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.DH"
        threat_id = "2147893984"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>461E4844E177B98FA19053599289ECCCA128D319E725152FCA5A040A5D22A122</p>" wide //weight: 1
        $x_1_2 = {34 36 31 45 34 38 34 34 45 31 37 37 42 39 38 46 41 31 39 30 35 33 35 39 39 32 38 39 45 43 43 43 41 31 32 38 44 33 31 39 45 37 32 35 31 35 32 46 43 41 35 41 30 34 30 41 35 44 32 32 41 31 32 32 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid461E4844E177B98FA19053599289ECCCA128D319E725152FCA5A040A5D22A122id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_DI_2147895125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.DI"
        threat_id = "2147895125"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>F1D0F45DBC3F4CA784D5D0D0DD8ADCD31AB5645BE00293FE6302CD0381F6527A</p>" wide //weight: 1
        $x_1_2 = {46 31 44 30 46 34 35 44 42 43 33 46 34 43 41 37 38 34 44 35 44 30 44 30 44 44 38 41 44 43 44 33 31 41 42 35 36 34 35 42 45 30 30 32 39 33 46 45 36 33 30 32 43 44 30 33 38 31 46 36 35 32 37 41 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidF1D0F45DBC3F4CA784D5D0D0DD8ADCD31AB5645BE00293FE6302CD0381F6527Aid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_DJ_2147895145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.DJ"
        threat_id = "2147895145"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>49D46141AF71989E7986FEE3A3417058AB55A63F3A27FB8094148248F4899A10</p>" wide //weight: 1
        $x_1_2 = {34 39 44 34 36 31 34 31 41 46 37 31 39 38 39 45 37 39 38 36 46 45 45 33 41 33 34 31 37 30 35 38 41 42 35 35 41 36 33 46 33 41 32 37 46 42 38 30 39 34 31 34 38 32 34 38 46 34 38 39 39 41 31 30 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid49D46141AF71989E7986FEE3A3417058AB55A63F3A27FB8094148248F4899A10id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_DK_2147895509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.DK"
        threat_id = "2147895509"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>657CB615E462F4D82AA8A0EACE0EAA9B9F0C0E168898585B638569608226441C</p>" wide //weight: 1
        $x_1_2 = {36 35 37 43 42 36 31 35 45 34 36 32 46 34 44 38 32 41 41 38 41 30 45 41 43 45 30 45 41 41 39 42 39 46 30 43 30 45 31 36 38 38 39 38 35 38 35 42 36 33 38 35 36 39 36 30 38 32 32 36 34 34 31 43 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid657CB615E462F4D82AA8A0EACE0EAA9B9F0C0E168898585B638569608226441Cid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_DL_2147895694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.DL"
        threat_id = "2147895694"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>C589F5D0AF2DF14EAFF5DAA494C8FB59F14D320BB31CF65E8D2BE4C8B98E764A</p>" wide //weight: 1
        $x_1_2 = {43 35 38 39 46 35 44 30 41 46 32 44 46 31 34 45 41 46 46 35 44 41 41 34 39 34 43 38 46 42 35 39 46 31 34 44 33 32 30 42 42 33 31 43 46 36 35 45 38 44 32 42 45 34 43 38 42 39 38 45 37 36 34 41 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidC589F5D0AF2DF14EAFF5DAA494C8FB59F14D320BB31CF65E8D2BE4C8B98E764Aid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_DM_2147896589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.DM"
        threat_id = "2147896589"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>B2DECD2A54DD80C0E48ABB0F98A5A09E71393A303AD4B2AEF8498CA6C9EEE628</p>" wide //weight: 1
        $x_1_2 = {42 32 44 45 43 44 32 41 35 34 44 44 38 30 43 30 45 34 38 41 42 42 30 46 39 38 41 35 41 30 39 45 37 31 33 39 33 41 33 30 33 41 44 34 42 32 41 45 46 38 34 39 38 43 41 36 43 39 45 45 45 36 32 38 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidB2DECD2A54DD80C0E48ABB0F98A5A09E71393A303AD4B2AEF8498CA6C9EEE628id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_DN_2147896593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.DN"
        threat_id = "2147896593"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>DE9F011510DD644D626456BE395A8A5857CB669F1982AC3A954575CA7E35E100</p>" wide //weight: 1
        $x_1_2 = {44 45 39 46 30 31 31 35 31 30 44 44 36 34 34 44 36 32 36 34 35 36 42 45 33 39 35 41 38 41 35 38 35 37 43 42 36 36 39 46 31 39 38 32 41 43 33 41 39 35 34 35 37 35 43 41 37 45 33 35 45 31 30 30 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidDE9F011510DD644D626456BE395A8A5857CB669F1982AC3A954575CA7E35E100id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_DO_2147896597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.DO"
        threat_id = "2147896597"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>2AECDEAAF9C4EBECAF787C971DC882E5270CBCB23E646027B814FAA60607CF6E</p>" wide //weight: 1
        $x_1_2 = {32 41 45 43 44 45 41 41 46 39 43 34 45 42 45 43 41 46 37 38 37 43 39 37 31 44 43 38 38 32 45 35 32 37 30 43 42 43 42 32 33 45 36 34 36 30 32 37 42 38 31 34 46 41 41 36 30 36 30 37 43 46 36 45 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid2AECDEAAF9C4EBECAF787C971DC882E5270CBCB23E646027B814FAA60607CF6Eid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_DP_2147896601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.DP"
        threat_id = "2147896601"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>12628E802B0C063E33AAB49BF53A41755CF00422723B0C122F1108A2B8436F54</p>" wide //weight: 1
        $x_1_2 = {31 32 36 32 38 45 38 30 32 42 30 43 30 36 33 45 33 33 41 41 42 34 39 42 46 35 33 41 34 31 37 35 35 43 46 30 30 34 32 32 37 32 33 42 30 43 31 32 32 46 31 31 30 38 41 32 42 38 34 33 36 46 35 34 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid12628E802B0C063E33AAB49BF53A41755CF00422723B0C122F1108A2B8436F54id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_DQ_2147897108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.DQ"
        threat_id = "2147897108"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>2731CB3EA9E8A1F2822C3D0DD5A7FD9955DE0C99E77A05C246D42E301D93A648</p>" wide //weight: 1
        $x_1_2 = {32 37 33 31 43 42 33 45 41 39 45 38 41 31 46 32 38 32 32 43 33 44 30 44 44 35 41 37 46 44 39 39 35 35 44 45 30 43 39 39 45 37 37 41 30 35 43 32 34 36 44 34 32 45 33 30 31 44 39 33 41 36 34 38 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid2731CB3EA9E8A1F2822C3D0DD5A7FD9955DE0C99E77A05C246D42E301D93A648id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_DR_2147897112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.DR"
        threat_id = "2147897112"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>A72D3895FF672D121212CBAE9B17A23504DFCC4443C835057BB9FC128A7F9023</p>" wide //weight: 1
        $x_1_2 = {41 37 32 44 33 38 39 35 46 46 36 37 32 44 31 32 31 32 31 32 43 42 41 45 39 42 31 37 41 32 33 35 30 34 44 46 43 43 34 34 34 33 43 38 33 35 30 35 37 42 42 39 46 43 31 32 38 41 37 46 39 30 32 33 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidA72D3895FF672D121212CBAE9B17A23504DFCC4443C835057BB9FC128A7F9023id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_DS_2147897116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.DS"
        threat_id = "2147897116"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>E13442A06BED50DC366E0EACEDD493BBF4DEC090ACF31A702E3EEFE15FCB225D</p>" wide //weight: 1
        $x_1_2 = {45 31 33 34 34 32 41 30 36 42 45 44 35 30 44 43 33 36 36 45 30 45 41 43 45 44 44 34 39 33 42 42 46 34 44 45 43 30 39 30 41 43 46 33 31 41 37 30 32 45 33 45 45 46 45 31 35 46 43 42 32 32 35 44 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidE13442A06BED50DC366E0EACEDD493BBF4DEC090ACF31A702E3EEFE15FCB225Did" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_DT_2147897223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.DT"
        threat_id = "2147897223"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>AA47F8CA532A6D71528143A4F9A3016E1BA07E155FE41DEBBEA94E2B2ED8546A</p>" wide //weight: 1
        $x_1_2 = {41 41 34 37 46 38 43 41 35 33 32 41 36 44 37 31 35 32 38 31 34 33 41 34 46 39 41 33 30 31 36 45 31 42 41 30 37 45 31 35 35 46 45 34 31 44 45 42 42 45 41 39 34 45 32 42 32 45 44 38 35 34 36 41 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidAA47F8CA532A6D71528143A4F9A3016E1BA07E155FE41DEBBEA94E2B2ED8546Aid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_DU_2147898501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.DU"
        threat_id = "2147898501"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>A2BE792BBE8077482156DC950840EA5F1CB0F8AB1C403BF6DDF863489C7CC60E</p>" wide //weight: 1
        $x_1_2 = {41 32 42 45 37 39 32 42 42 45 38 30 37 37 34 38 32 31 35 36 44 43 39 35 30 38 34 30 45 41 35 46 31 43 42 30 46 38 41 42 31 43 34 30 33 42 46 36 44 44 46 38 36 33 34 38 39 43 37 43 43 36 30 45 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidA2BE792BBE8077482156DC950840EA5F1CB0F8AB1C403BF6DDF863489C7CC60Eid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_DV_2147898505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.DV"
        threat_id = "2147898505"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>E24F024A739BF4CC1A40FD970A11154D231FB5DF0D401C17E4C2439AA7903463</p>" wide //weight: 1
        $x_1_2 = {45 32 34 46 30 32 34 41 37 33 39 42 46 34 43 43 31 41 34 30 46 44 39 37 30 41 31 31 31 35 34 44 32 33 31 46 42 35 44 46 30 44 34 30 31 43 31 37 45 34 43 32 34 33 39 41 41 37 39 30 33 34 36 33 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidE24F024A739BF4CC1A40FD970A11154D231FB5DF0D401C17E4C2439AA7903463id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_DW_2147898509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.DW"
        threat_id = "2147898509"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>AD529139F9C08CECFF34C92A6D4D03324B8CD450BC0BEEDC071297BBCB596E59</p>" wide //weight: 1
        $x_1_2 = {41 44 35 32 39 31 33 39 46 39 43 30 38 43 45 43 46 46 33 34 43 39 32 41 36 44 34 44 30 33 33 32 34 42 38 43 44 34 35 30 42 43 30 42 45 45 44 43 30 37 31 32 39 37 42 42 43 42 35 39 36 45 35 39 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidAD529139F9C08CECFF34C92A6D4D03324B8CD450BC0BEEDC071297BBCB596E59id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_DX_2147898513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.DX"
        threat_id = "2147898513"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>90AD660309EDF9786F15C85EE20F7BBEB82A4D727A0B619E9FE791F5CA049E09</p>" wide //weight: 1
        $x_1_2 = {39 30 41 44 36 36 30 33 30 39 45 44 46 39 37 38 36 46 31 35 43 38 35 45 45 32 30 46 37 42 42 45 42 38 32 41 34 44 37 32 37 41 30 42 36 31 39 45 39 46 45 37 39 31 46 35 43 41 30 34 39 45 30 39 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid90AD660309EDF9786F15C85EE20F7BBEB82A4D727A0B619E9FE791F5CA049E09id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_DY_2147898517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.DY"
        threat_id = "2147898517"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>7FEBE7DA5E3FADF691ABC60DE0F15D4EEC0BF089845487631594822F4F516222</p>" wide //weight: 1
        $x_1_2 = {37 46 45 42 45 37 44 41 35 45 33 46 41 44 46 36 39 31 41 42 43 36 30 44 45 30 46 31 35 44 34 45 45 43 30 42 46 30 38 39 38 34 35 34 38 37 36 33 31 35 39 34 38 32 32 46 34 46 35 31 36 32 32 32 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid7FEBE7DA5E3FADF691ABC60DE0F15D4EEC0BF089845487631594822F4F516222id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_DZ_2147898521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.DZ"
        threat_id = "2147898521"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>B7A49CA7FF4A5DFE23DD437A9C81C430831AE0FE99B389E6A2991BC38915B272</p>" wide //weight: 1
        $x_1_2 = {42 37 41 34 39 43 41 37 46 46 34 41 35 44 46 45 32 33 44 44 34 33 37 41 39 43 38 31 43 34 33 30 38 33 31 41 45 30 46 45 39 39 42 33 38 39 45 36 41 32 39 39 31 42 43 33 38 39 31 35 42 32 37 32 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidB7A49CA7FF4A5DFE23DD437A9C81C430831AE0FE99B389E6A2991BC38915B272id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_EA_2147898525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.EA"
        threat_id = "2147898525"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>0BF0BA66030916F61BB7D9E954FB98A8F973DB6531F18EB6CEE006D7E275B906</p>" wide //weight: 1
        $x_1_2 = {30 42 46 30 42 41 36 36 30 33 30 39 31 36 46 36 31 42 42 37 44 39 45 39 35 34 46 42 39 38 41 38 46 39 37 33 44 42 36 35 33 31 46 31 38 45 42 36 43 45 45 30 30 36 44 37 45 32 37 35 42 39 30 36 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid0BF0BA66030916F61BB7D9E954FB98A8F973DB6531F18EB6CEE006D7E275B906id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_EB_2147898529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.EB"
        threat_id = "2147898529"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>7CB85C41D6E3FC9602FB8D79B955820AC4EEF41F29F2177B9750C129935F216F</p>" wide //weight: 1
        $x_1_2 = {37 43 42 38 35 43 34 31 44 36 45 33 46 43 39 36 30 32 46 42 38 44 37 39 42 39 35 35 38 32 30 41 43 34 45 45 46 34 31 46 32 39 46 32 31 37 37 42 39 37 35 30 43 31 32 39 39 33 35 46 32 31 36 46 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid7CB85C41D6E3FC9602FB8D79B955820AC4EEF41F29F2177B9750C129935F216Fid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_EC_2147898733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.EC"
        threat_id = "2147898733"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>D27A7B3711CD1442A8FAC19BB5780FF291101F6286A62AD21E5F7F08BD5F5F1B</p>" wide //weight: 1
        $x_1_2 = {44 32 37 41 37 42 33 37 31 31 43 44 31 34 34 32 41 38 46 41 43 31 39 42 42 35 37 38 30 46 46 32 39 31 31 30 31 46 36 32 38 36 41 36 32 41 44 32 31 45 35 46 37 46 30 38 42 44 35 46 35 46 31 42 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidD27A7B3711CD1442A8FAC19BB5780FF291101F6286A62AD21E5F7F08BD5F5F1Bid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_ED_2147898737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.ED"
        threat_id = "2147898737"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>7DFFA421CF18F77F3BB974A27646DE9DD985C1943584B48433BEB4A96F118621</p>" wide //weight: 1
        $x_1_2 = {37 44 46 46 41 34 32 31 43 46 31 38 46 37 37 46 33 42 42 39 37 34 41 32 37 36 34 36 44 45 39 44 44 39 38 35 43 31 39 34 33 35 38 34 42 34 38 34 33 33 42 45 42 34 41 39 36 46 31 31 38 36 32 31 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid7DFFA421CF18F77F3BB974A27646DE9DD985C1943584B48433BEB4A96F118621id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_EE_2147899154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.EE"
        threat_id = "2147899154"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>02C75E60211314F4A69C323A3CE334D75C72CD8C742F3ED168447405C541DF05</p>" wide //weight: 1
        $x_1_2 = {30 32 43 37 35 45 36 30 32 31 31 33 31 34 46 34 41 36 39 43 33 32 33 41 33 43 45 33 33 34 44 37 35 43 37 32 43 44 38 43 37 34 32 46 33 45 44 31 36 38 34 34 37 34 30 35 43 35 34 31 44 46 30 35 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid02C75E60211314F4A69C323A3CE334D75C72CD8C742F3ED168447405C541DF05id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_EF_2147900281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.EF"
        threat_id = "2147900281"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>1C054B722BCBF41A918EF3C485712742088F5C3E81B2FDD91ADEA6BA55F4A856</p>" wide //weight: 1
        $x_1_2 = {31 43 30 35 34 42 37 32 32 42 43 42 46 34 31 41 39 31 38 45 46 33 43 34 38 35 37 31 32 37 34 32 30 38 38 46 35 43 33 45 38 31 42 32 46 44 44 39 31 41 44 45 41 36 42 41 35 35 46 34 41 38 35 36 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid1C054B722BCBF41A918EF3C485712742088F5C3E81B2FDD91ADEA6BA55F4A856id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_EG_2147900285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.EG"
        threat_id = "2147900285"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>A6FA4856508F2198468A7FCB4F194D7B52BE632364D81CCE6F4DAD6FABBF3A49</p>" wide //weight: 1
        $x_1_2 = {41 36 46 41 34 38 35 36 35 30 38 46 32 31 39 38 34 36 38 41 37 46 43 42 34 46 31 39 34 44 37 42 35 32 42 45 36 33 32 33 36 34 44 38 31 43 43 45 36 46 34 44 41 44 36 46 41 42 42 46 33 41 34 39 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidA6FA4856508F2198468A7FCB4F194D7B52BE632364D81CCE6F4DAD6FABBF3A49id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_EH_2147902728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.EH"
        threat_id = "2147902728"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>98D120C9033653042E290627914B890A3291013F7377A976A028051C52440C71</p>" wide //weight: 1
        $x_1_2 = {39 38 44 31 32 30 43 39 30 33 33 36 35 33 30 34 32 45 32 39 30 36 32 37 39 31 34 42 38 39 30 41 33 32 39 31 30 31 33 46 37 33 37 37 41 39 37 36 41 30 32 38 30 35 31 43 35 32 34 34 30 43 37 31 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid98D120C9033653042E290627914B890A3291013F7377A976A028051C52440C71id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_EI_2147903399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.EI"
        threat_id = "2147903399"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>59052DE8288FE054576FB2D8ADE27E35AD9269F5AB4BED99BDC019B81D40B97C</p>" wide //weight: 1
        $x_1_2 = {35 39 30 35 32 44 45 38 32 38 38 46 45 30 35 34 35 37 36 46 42 32 44 38 41 44 45 32 37 45 33 35 41 44 39 32 36 39 46 35 41 42 34 42 45 44 39 39 42 44 43 30 31 39 42 38 31 44 34 30 42 39 37 43 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid59052DE8288FE054576FB2D8ADE27E35AD9269F5AB4BED99BDC019B81D40B97Cid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_EJ_2147903952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.EJ"
        threat_id = "2147903952"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>E5BBFAD2DB3FB497EA03612B2428F927FD8A9B3333D524FD51D43B029B787057</p>" wide //weight: 1
        $x_1_2 = {45 35 42 42 46 41 44 32 44 42 33 46 42 34 39 37 45 41 30 33 36 31 32 42 32 34 32 38 46 39 32 37 46 44 38 41 39 42 33 33 33 33 44 35 32 34 46 44 35 31 44 34 33 42 30 32 39 42 37 38 37 30 35 37 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidE5BBFAD2DB3FB497EA03612B2428F927FD8A9B3333D524FD51D43B029B787057id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_EK_2147904886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.EK"
        threat_id = "2147904886"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>ECBFA0EB44135FDB09BDE1F5EE8F95CE3F1009385CCA2FF3FEF4CB09C15BA854</p>" wide //weight: 1
        $x_1_2 = {45 43 42 46 41 30 45 42 34 34 31 33 35 46 44 42 30 39 42 44 45 31 46 35 45 45 38 46 39 35 43 45 33 46 31 30 30 39 33 38 35 43 43 41 32 46 46 33 46 45 46 34 43 42 30 39 43 31 35 42 41 38 35 34 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidECBFA0EB44135FDB09BDE1F5EE8F95CE3F1009385CCA2FF3FEF4CB09C15BA854id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_EL_2147905298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.EL"
        threat_id = "2147905298"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>B29F3EB9D89D940BFB8293B67977B9A24F74E2EDCF854AE7376D1BCE2BC85B70</p>" wide //weight: 1
        $x_1_2 = {42 32 39 46 33 45 42 39 44 38 39 44 39 34 30 42 46 42 38 32 39 33 42 36 37 39 37 37 42 39 41 32 34 46 37 34 45 32 45 44 43 46 38 35 34 41 45 37 33 37 36 44 31 42 43 45 32 42 43 38 35 42 37 30 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidB29F3EB9D89D940BFB8293B67977B9A24F74E2EDCF854AE7376D1BCE2BC85B70id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_EM_2147905302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.EM"
        threat_id = "2147905302"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>4D598799696AD5399FABF7D40C4D1BE9F05D74CFB311047D7391AC0BF64BED47</p>" wide //weight: 1
        $x_1_2 = {34 44 35 39 38 37 39 39 36 39 36 41 44 35 33 39 39 46 41 42 46 37 44 34 30 43 34 44 31 42 45 39 46 30 35 44 37 34 43 46 42 33 31 31 30 34 37 44 37 33 39 31 41 43 30 42 46 36 34 42 45 44 34 37 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid4D598799696AD5399FABF7D40C4D1BE9F05D74CFB311047D7391AC0BF64BED47id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_EN_2147905306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.EN"
        threat_id = "2147905306"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>5596A55062A4232F5AA55C2F7C4DF0AC1EAD10B78D4055A3328AD142A42B555E</p>" wide //weight: 1
        $x_1_2 = {35 35 39 36 41 35 35 30 36 32 41 34 32 33 32 46 35 41 41 35 35 43 32 46 37 43 34 44 46 30 41 43 31 45 41 44 31 30 42 37 38 44 34 30 35 35 41 33 33 32 38 41 44 31 34 32 41 34 32 42 35 35 35 45 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid5596A55062A4232F5AA55C2F7C4DF0AC1EAD10B78D4055A3328AD142A42B555Eid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_EO_2147905569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.EO"
        threat_id = "2147905569"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>6520A79F5A832F9D4238C2C2841D89A3246F7EF2B0185C735267D7D41F5D9129</p>" wide //weight: 1
        $x_1_2 = {36 35 32 30 41 37 39 46 35 41 38 33 32 46 39 44 34 32 33 38 43 32 43 32 38 34 31 44 38 39 41 33 32 34 36 46 37 45 46 32 42 30 31 38 35 43 37 33 35 32 36 37 44 37 44 34 31 46 35 44 39 31 32 39 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid6520A79F5A832F9D4238C2C2841D89A3246F7EF2B0185C735267D7D41F5D9129id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_EP_2147905837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.EP"
        threat_id = "2147905837"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>8D545FF434C6B990054C6181BFB409CBE394A697EB703877499F97AD4462A811</p>" wide //weight: 1
        $x_1_2 = {38 44 35 34 35 46 46 34 33 34 43 36 42 39 39 30 30 35 34 43 36 31 38 31 42 46 42 34 30 39 43 42 45 33 39 34 41 36 39 37 45 42 37 30 33 38 37 37 34 39 39 46 39 37 41 44 34 34 36 32 41 38 31 31 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid8D545FF434C6B990054C6181BFB409CBE394A697EB703877499F97AD4462A811id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_EQ_2147905938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.EQ"
        threat_id = "2147905938"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>7C35408411AEEBD53CDBCEBAB167D7B22F1E66614E89DFCB62EE835416F60E1B</p>" wide //weight: 1
        $x_1_2 = {37 43 33 35 34 30 38 34 31 31 41 45 45 42 44 35 33 43 44 42 43 45 42 41 42 31 36 37 44 37 42 32 32 46 31 45 36 36 36 31 34 45 38 39 44 46 43 42 36 32 45 45 38 33 35 34 31 36 46 36 30 45 31 42 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid7C35408411AEEBD53CDBCEBAB167D7B22F1E66614E89DFCB62EE835416F60E1Bid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_ER_2147906025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.ER"
        threat_id = "2147906025"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>A8AD0FD4C931CDAA1408D5A60CBF38CEDF46B41E19A8A55E4EF1F1848AF3416A</p>" wide //weight: 1
        $x_1_2 = {41 38 41 44 30 46 44 34 43 39 33 31 43 44 41 41 31 34 30 38 44 35 41 36 30 43 42 46 33 38 43 45 44 46 34 36 42 34 31 45 31 39 41 38 41 35 35 45 34 45 46 31 46 31 38 34 38 41 46 33 34 31 36 41 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidA8AD0FD4C931CDAA1408D5A60CBF38CEDF46B41E19A8A55E4EF1F1848AF3416Aid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_ES_2147906141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.ES"
        threat_id = "2147906141"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>2793D009872AF80ED9B1A461F7B9BD6209744047DC1707A42CB622053716AD4B</p>" wide //weight: 1
        $x_1_2 = {32 37 39 33 44 30 30 39 38 37 32 41 46 38 30 45 44 39 42 31 41 34 36 31 46 37 42 39 42 44 36 32 30 39 37 34 34 30 34 37 44 43 31 37 30 37 41 34 32 43 42 36 32 32 30 35 33 37 31 36 41 44 34 42 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid2793D009872AF80ED9B1A461F7B9BD6209744047DC1707A42CB622053716AD4Bid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_ET_2147906145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.ET"
        threat_id = "2147906145"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>AEA72DFCF492037A6D15755A74645C7D8E674E342BACA9F9070A3FB74117EC31</p>" wide //weight: 1
        $x_1_2 = {41 45 41 37 32 44 46 43 46 34 39 32 30 33 37 41 36 44 31 35 37 35 35 41 37 34 36 34 35 43 37 44 38 45 36 37 34 45 33 34 32 42 41 43 41 39 46 39 30 37 30 41 33 46 42 37 34 31 31 37 45 43 33 31 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidAEA72DFCF492037A6D15755A74645C7D8E674E342BACA9F9070A3FB74117EC31id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_EU_2147906149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.EU"
        threat_id = "2147906149"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>BD0FC8C016657DE254C0F48AA3472E11B8C92F96DAF66F971ABF5B8AE7409E2F</p>" wide //weight: 1
        $x_1_2 = {42 44 30 46 43 38 43 30 31 36 36 35 37 44 45 32 35 34 43 30 46 34 38 41 41 33 34 37 32 45 31 31 42 38 43 39 32 46 39 36 44 41 46 36 36 46 39 37 31 41 42 46 35 42 38 41 45 37 34 30 39 45 32 46 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidBD0FC8C016657DE254C0F48AA3472E11B8C92F96DAF66F971ABF5B8AE7409E2Fid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_EW_2147907283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.EW"
        threat_id = "2147907283"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>4CDE9AA5707C619C241A2F27E0F3378E6A5CC6AD031EADC40C36F1F300DB8D5B</p>" wide //weight: 1
        $x_1_2 = {34 43 44 45 39 41 41 35 37 30 37 43 36 31 39 43 32 34 31 41 32 46 32 37 45 30 46 33 33 37 38 45 36 41 35 43 43 36 41 44 30 33 31 45 41 44 43 34 30 43 33 36 46 31 46 33 30 30 44 42 38 44 35 42 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid4CDE9AA5707C619C241A2F27E0F3378E6A5CC6AD031EADC40C36F1F300DB8D5Bid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_EX_2147907287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.EX"
        threat_id = "2147907287"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>9A8B9576F0B3846B4CA8B4FAF9F50F633CE731BBC860E76C09ED31FC1A1ACF2A</p>" wide //weight: 1
        $x_1_2 = {39 41 38 42 39 35 37 36 46 30 42 33 38 34 36 42 34 43 41 38 42 34 46 41 46 39 46 35 30 46 36 33 33 43 45 37 33 31 42 42 43 38 36 30 45 37 36 43 30 39 45 44 33 31 46 43 31 41 31 41 43 46 32 41 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid9A8B9576F0B3846B4CA8B4FAF9F50F633CE731BBC860E76C09ED31FC1A1ACF2Aid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_EY_2147907291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.EY"
        threat_id = "2147907291"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>358AC0F6C813DD4FD243524F040E2F77969278274BD8A8945B5041A249786E32</p>" wide //weight: 1
        $x_1_2 = {33 35 38 41 43 30 46 36 43 38 31 33 44 44 34 46 44 32 34 33 35 32 34 46 30 34 30 45 32 46 37 37 39 36 39 32 37 38 32 37 34 42 44 38 41 38 39 34 35 42 35 30 34 31 41 32 34 39 37 38 36 45 33 32 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid358AC0F6C813DD4FD243524F040E2F77969278274BD8A8945B5041A249786E32id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_EZ_2147907335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.EZ"
        threat_id = "2147907335"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>285CFEC2BC80A8A698B3E4E0C86A0FCB329569DAA16EA11FD028774E26BDD97D</p>" wide //weight: 1
        $x_1_2 = {32 38 35 43 46 45 43 32 42 43 38 30 41 38 41 36 39 38 42 33 45 34 45 30 43 38 36 41 30 46 43 42 33 32 39 35 36 39 44 41 41 31 36 45 41 31 31 46 44 30 32 38 37 37 34 45 32 36 42 44 44 39 37 44 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid285CFEC2BC80A8A698B3E4E0C86A0FCB329569DAA16EA11FD028774E26BDD97Did" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_FA_2147907403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.FA"
        threat_id = "2147907403"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>DCBB9DDEA640A6A68FD8205B7C160D6F91FF9C3B0AE73ABDB6D426543BCAFA7A</p>" wide //weight: 1
        $x_1_2 = {44 43 42 42 39 44 44 45 41 36 34 30 41 36 41 36 38 46 44 38 32 30 35 42 37 43 31 36 30 44 36 46 39 31 46 46 39 43 33 42 30 41 45 37 33 41 42 44 42 36 44 34 32 36 35 34 33 42 43 41 46 41 37 41 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidDCBB9DDEA640A6A68FD8205B7C160D6F91FF9C3B0AE73ABDB6D426543BCAFA7Aid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_FB_2147907407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.FB"
        threat_id = "2147907407"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>BE34052204E43C950AF5114D0B52F359C8FED65BFBD7B80097B96FD554362334</p>" wide //weight: 1
        $x_1_2 = {42 45 33 34 30 35 32 32 30 34 45 34 33 43 39 35 30 41 46 35 31 31 34 44 30 42 35 32 46 33 35 39 43 38 46 45 44 36 35 42 46 42 44 37 42 38 30 30 39 37 42 39 36 46 44 35 35 34 33 36 32 33 33 34 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidBE34052204E43C950AF5114D0B52F359C8FED65BFBD7B80097B96FD554362334id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_FC_2147907411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.FC"
        threat_id = "2147907411"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>14607D9D78CDD2CE718B6C7F4C4087A6F8EE37E37EA93830B6D02AA0DDB88266</p>" wide //weight: 1
        $x_1_2 = {31 34 36 30 37 44 39 44 37 38 43 44 44 32 43 45 37 31 38 42 36 43 37 46 34 43 34 30 38 37 41 36 46 38 45 45 33 37 45 33 37 45 41 39 33 38 33 30 42 36 44 30 32 41 41 30 44 44 42 38 38 32 36 36 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid14607D9D78CDD2CE718B6C7F4C4087A6F8EE37E37EA93830B6D02AA0DDB88266id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_FD_2147907750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.FD"
        threat_id = "2147907750"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>ED27769A3F1FCD0A16D9D40776770ACFD694BDEDBD7D926F28A77C185792B852</p>" wide //weight: 1
        $x_1_2 = {45 44 32 37 37 36 39 41 33 46 31 46 43 44 30 41 31 36 44 39 44 34 30 37 37 36 37 37 30 41 43 46 44 36 39 34 42 44 45 44 42 44 37 44 39 32 36 46 32 38 41 37 37 43 31 38 35 37 39 32 42 38 35 32 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidED27769A3F1FCD0A16D9D40776770ACFD694BDEDBD7D926F28A77C185792B852id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_FE_2147908364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.FE"
        threat_id = "2147908364"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>B346F0ECF601FC1E2EF530602790B1EDA7A61E1AE23110C68F513F9F9646C910</p>" wide //weight: 1
        $x_1_2 = {42 33 34 36 46 30 45 43 46 36 30 31 46 43 31 45 32 45 46 35 33 30 36 30 32 37 39 30 42 31 45 44 41 37 41 36 31 45 31 41 45 32 33 31 31 30 43 36 38 46 35 31 33 46 39 46 39 36 34 36 43 39 31 30 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidB346F0ECF601FC1E2EF530602790B1EDA7A61E1AE23110C68F513F9F9646C910id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_FF_2147909575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.FF"
        threat_id = "2147909575"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>1097C77415E419164E4E5229CF57B19586C2F30C1050306BF4127CDC6391D44D</p>" wide //weight: 1
        $x_1_2 = {31 30 39 37 43 37 37 34 31 35 45 34 31 39 31 36 34 45 34 45 35 32 32 39 43 46 35 37 42 31 39 35 38 36 43 32 46 33 30 43 31 30 35 30 33 30 36 42 46 34 31 32 37 43 44 43 36 33 39 31 44 34 34 44 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid1097C77415E419164E4E5229CF57B19586C2F30C1050306BF4127CDC6391D44Did" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_FG_2147909579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.FG"
        threat_id = "2147909579"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>1D1C4B6CC456727CFD622AC25E4E81FF3826AECD75A4E8A21E4D293EBBB2A14D</p>" wide //weight: 1
        $x_1_2 = {31 44 31 43 34 42 36 43 43 34 35 36 37 32 37 43 46 44 36 32 32 41 43 32 35 45 34 45 38 31 46 46 33 38 32 36 41 45 43 44 37 35 41 34 45 38 41 32 31 45 34 44 32 39 33 45 42 42 42 32 41 31 34 44 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid1D1C4B6CC456727CFD622AC25E4E81FF3826AECD75A4E8A21E4D293EBBB2A14Did" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_FH_2147909583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.FH"
        threat_id = "2147909583"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>9796CE1E72A8874D594F6573F44C94FB649473B4194DCD80C406BFE88E4B3662</p>" wide //weight: 1
        $x_1_2 = {39 37 39 36 43 45 31 45 37 32 41 38 38 37 34 44 35 39 34 46 36 35 37 33 46 34 34 43 39 34 46 42 36 34 39 34 37 33 42 34 31 39 34 44 43 44 38 30 43 34 30 36 42 46 45 38 38 45 34 42 33 36 36 32 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid9796CE1E72A8874D594F6573F44C94FB649473B4194DCD80C406BFE88E4B3662id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_FI_2147909587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.FI"
        threat_id = "2147909587"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>A7D21906457B8877A15F4AD0F236242FE431966C3D17B14A8E8CD15B4B60B56E</p>" wide //weight: 1
        $x_1_2 = {41 37 44 32 31 39 30 36 34 35 37 42 38 38 37 37 41 31 35 46 34 41 44 30 46 32 33 36 32 34 32 46 45 34 33 31 39 36 36 43 33 44 31 37 42 31 34 41 38 45 38 43 44 31 35 42 34 42 36 30 42 35 36 45 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidA7D21906457B8877A15F4AD0F236242FE431966C3D17B14A8E8CD15B4B60B56Eid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_FJ_2147910395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.FJ"
        threat_id = "2147910395"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>91A120F1D2E4A2DAEA82E3043D98AFE58DAAFC1A639ADFB624C45D9BDA148D22</p>" wide //weight: 1
        $x_1_2 = {39 31 41 31 32 30 46 31 44 32 45 34 41 32 44 41 45 41 38 32 45 33 30 34 33 44 39 38 41 46 45 35 38 44 41 41 46 43 31 41 36 33 39 41 44 46 42 36 32 34 43 34 35 44 39 42 44 41 31 34 38 44 32 32 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid91A120F1D2E4A2DAEA82E3043D98AFE58DAAFC1A639ADFB624C45D9BDA148D22id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_FK_2147910398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.FK"
        threat_id = "2147910398"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>3C588D36EF676201701B0B8EA1F8046E0B2372EBCF900008E80B0DE02F39DD25</p>" wide //weight: 1
        $x_1_2 = {33 43 35 38 38 44 33 36 45 46 36 37 36 32 30 31 37 30 31 42 30 42 38 45 41 31 46 38 30 34 36 45 30 42 32 33 37 32 45 42 43 46 39 30 30 30 30 38 45 38 30 42 30 44 45 30 32 46 33 39 44 44 32 35 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid3C588D36EF676201701B0B8EA1F8046E0B2372EBCF900008E80B0DE02F39DD25id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_FL_2147910716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.FL"
        threat_id = "2147910716"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>A466C1720D92FF9A57241E24BA38E2AF9896FCD250FCC85E7E43E05871FB655C</p>" wide //weight: 1
        $x_1_2 = {41 34 36 36 43 31 37 32 30 44 39 32 46 46 39 41 35 37 32 34 31 45 32 34 42 41 33 38 45 32 41 46 39 38 39 36 46 43 44 32 35 30 46 43 43 38 35 45 37 45 34 33 45 30 35 38 37 31 46 42 36 35 35 43 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidA466C1720D92FF9A57241E24BA38E2AF9896FCD250FCC85E7E43E05871FB655Cid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_FM_2147910720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.FM"
        threat_id = "2147910720"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>88A612B3887D57A7FA3D48F5E3EDF952E4BE48E0972FC6456FBBCFF198CC8620</p>" wide //weight: 1
        $x_1_2 = {38 38 41 36 31 32 42 33 38 38 37 44 35 37 41 37 46 41 33 44 34 38 46 35 45 33 45 44 46 39 35 32 45 34 42 45 34 38 45 30 39 37 32 46 43 36 34 35 36 46 42 42 43 46 46 31 39 38 43 43 38 36 32 30 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid88A612B3887D57A7FA3D48F5E3EDF952E4BE48E0972FC6456FBBCFF198CC8620id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_FN_2147910867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.FN"
        threat_id = "2147910867"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>36F186C6FDCAAC0CF122E234B5D15F3F42F73568745F251C1306D71EBCA96817</p>" wide //weight: 1
        $x_1_2 = {33 36 46 31 38 36 43 36 46 44 43 41 41 43 30 43 46 31 32 32 45 32 33 34 42 35 44 31 35 46 33 46 34 32 46 37 33 35 36 38 37 34 35 46 32 35 31 43 31 33 30 36 44 37 31 45 42 43 41 39 36 38 31 37 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid36F186C6FDCAAC0CF122E234B5D15F3F42F73568745F251C1306D71EBCA96817id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_FO_2147911108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.FO"
        threat_id = "2147911108"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>6C532A1EEBC9225639D91BDECFE9F7B0ADC0582083C5C0BE188F43CC0F482A40</p>" wide //weight: 1
        $x_1_2 = {36 43 35 33 32 41 31 45 45 42 43 39 32 32 35 36 33 39 44 39 31 42 44 45 43 46 45 39 46 37 42 30 41 44 43 30 35 38 32 30 38 33 43 35 43 30 42 45 31 38 38 46 34 33 43 43 30 46 34 38 32 41 34 30 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid6C532A1EEBC9225639D91BDECFE9F7B0ADC0582083C5C0BE188F43CC0F482A40id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_FP_2147911433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.FP"
        threat_id = "2147911433"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>A7A86A6C92CC034E621B58C4DDDD3542957C8019A141C6F4D138D8451882654A</p>" wide //weight: 1
        $x_1_2 = {41 37 41 38 36 41 36 43 39 32 43 43 30 33 34 45 36 32 31 42 35 38 43 34 44 44 44 44 33 35 34 32 39 35 37 43 38 30 31 39 41 31 34 31 43 36 46 34 44 31 33 38 44 38 34 35 31 38 38 32 36 35 34 41 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidA7A86A6C92CC034E621B58C4DDDD3542957C8019A141C6F4D138D8451882654Aid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_FQ_2147911563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.FQ"
        threat_id = "2147911563"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>2D164BEB09DF775C543F52C7AD8755B96FBB3A19C8AEAB0C93EFCE3C74E4A703</p>" wide //weight: 1
        $x_1_2 = {32 44 31 36 34 42 45 42 30 39 44 46 37 37 35 43 35 34 33 46 35 32 43 37 41 44 38 37 35 35 42 39 36 46 42 42 33 41 31 39 43 38 41 45 41 42 30 43 39 33 45 46 43 45 33 43 37 34 45 34 41 37 30 33 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid2D164BEB09DF775C543F52C7AD8755B96FBB3A19C8AEAB0C93EFCE3C74E4A703id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_FR_2147911567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.FR"
        threat_id = "2147911567"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>A504DF3588EC05145E2C42EF8F214F3246D5E3526B05ECCC21EDC6783992C43E</p>" wide //weight: 1
        $x_1_2 = {41 35 30 34 44 46 33 35 38 38 45 43 30 35 31 34 35 45 32 43 34 32 45 46 38 46 32 31 34 46 33 32 34 36 44 35 45 33 35 32 36 42 30 35 45 43 43 43 32 31 45 44 43 36 37 38 33 39 39 32 43 34 33 45 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidA504DF3588EC05145E2C42EF8F214F3246D5E3526B05ECCC21EDC6783992C43Eid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_FS_2147911571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.FS"
        threat_id = "2147911571"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>14CEE2E9F5B0F5D10378ED08C7C52552EF425D12CB03EE7462E938AE82735F2B</p>" wide //weight: 1
        $x_1_2 = {31 34 43 45 45 32 45 39 46 35 42 30 46 35 44 31 30 33 37 38 45 44 30 38 43 37 43 35 32 35 35 32 45 46 34 32 35 44 31 32 43 42 30 33 45 45 37 34 36 32 45 39 33 38 41 45 38 32 37 33 35 46 32 42 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid14CEE2E9F5B0F5D10378ED08C7C52552EF425D12CB03EE7462E938AE82735F2Bid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_FT_2147911575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.FT"
        threat_id = "2147911575"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>F01DE6CE6E065F6D4D1022311EBD62238ECC0B06127EB7DD72B8CEE084CFBA42</p>" wide //weight: 1
        $x_1_2 = {46 30 31 44 45 36 43 45 36 45 30 36 35 46 36 44 34 44 31 30 32 32 33 31 31 45 42 44 36 32 32 33 38 45 43 43 30 42 30 36 31 32 37 45 42 37 44 44 37 32 42 38 43 45 45 30 38 34 43 46 42 41 34 32 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidF01DE6CE6E065F6D4D1022311EBD62238ECC0B06127EB7DD72B8CEE084CFBA42id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_FU_2147911703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.FU"
        threat_id = "2147911703"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>F6B2E01CFA4D3F2DB75E4EDD07EC28BF793E541A9674C3E6A66E1CDA9D931A13</p>" wide //weight: 1
        $x_1_2 = {46 36 42 32 45 30 31 43 46 41 34 44 33 46 32 44 42 37 35 45 34 45 44 44 30 37 45 43 32 38 42 46 37 39 33 45 35 34 31 41 39 36 37 34 43 33 45 36 41 36 36 45 31 43 44 41 39 44 39 33 31 41 31 33 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidF6B2E01CFA4D3F2DB75E4EDD07EC28BF793E541A9674C3E6A66E1CDA9D931A13id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_FV_2147913882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.FV"
        threat_id = "2147913882"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>DDD155B43289399E7770F6B8F6AD5D6F5197FAD60F2F823797116AC36A0DEA02</p>" wide //weight: 1
        $x_1_2 = {44 44 44 31 35 35 42 34 33 32 38 39 33 39 39 45 37 37 37 30 46 36 42 38 46 36 41 44 35 44 36 46 35 31 39 37 46 41 44 36 30 46 32 46 38 32 33 37 39 37 31 31 36 41 43 33 36 41 30 44 45 41 30 32 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidDDD155B43289399E7770F6B8F6AD5D6F5197FAD60F2F823797116AC36A0DEA02id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_FW_2147913886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.FW"
        threat_id = "2147913886"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>10FCD323158B14E6BD41CB00CB98AD8E8FE0C9D9B78150F008350BCAC84C1B5D</p>" wide //weight: 1
        $x_1_2 = {31 30 46 43 44 33 32 33 31 35 38 42 31 34 45 36 42 44 34 31 43 42 30 30 43 42 39 38 41 44 38 45 38 46 45 30 43 39 44 39 42 37 38 31 35 30 46 30 30 38 33 35 30 42 43 41 43 38 34 43 31 42 35 44 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid10FCD323158B14E6BD41CB00CB98AD8E8FE0C9D9B78150F008350BCAC84C1B5Did" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_FX_2147913890_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.FX"
        threat_id = "2147913890"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>1E62672989582C08F5C5F1B0185ACF4281A571CE4115C0EB019B972187B18855</p>" wide //weight: 1
        $x_1_2 = {31 45 36 32 36 37 32 39 38 39 35 38 32 43 30 38 46 35 43 35 46 31 42 30 31 38 35 41 43 46 34 32 38 31 41 35 37 31 43 45 34 31 31 35 43 30 45 42 30 31 39 42 39 37 32 31 38 37 42 31 38 38 35 35 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid1E62672989582C08F5C5F1B0185ACF4281A571CE4115C0EB019B972187B18855id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_FY_2147915542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.FY"
        threat_id = "2147915542"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>9500B1A73716BCF40745086F7184A33EA0141B7D3F852431C8FDD2E1E8FAF927</p>" wide //weight: 1
        $x_1_2 = {39 35 30 30 42 31 41 37 33 37 31 36 42 43 46 34 30 37 34 35 30 38 36 46 37 31 38 34 41 33 33 45 41 30 31 34 31 42 37 44 33 46 38 35 32 34 33 31 43 38 46 44 44 32 45 31 45 38 46 41 46 39 32 37 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid9500B1A73716BCF40745086F7184A33EA0141B7D3F852431C8FDD2E1E8FAF927id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_FZ_2147916041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.FZ"
        threat_id = "2147916041"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>6055FA73B7D94FE77A34502A664D95A439F18A72C0042915A7EEBE09F4ACF023</p>" wide //weight: 1
        $x_1_2 = {36 30 35 35 46 41 37 33 42 37 44 39 34 46 45 37 37 41 33 34 35 30 32 41 36 36 34 44 39 35 41 34 33 39 46 31 38 41 37 32 43 30 30 34 32 39 31 35 41 37 45 45 42 45 30 39 46 34 41 43 46 30 32 33 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid6055FA73B7D94FE77A34502A664D95A439F18A72C0042915A7EEBE09F4ACF023id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_GA_2147917463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.GA"
        threat_id = "2147917463"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>D4CDADA0C4345AFDE8A1FD2731D9B367D635330273E25FB1DBFD468608F15404</p>" wide //weight: 1
        $x_1_2 = {44 34 43 44 41 44 41 30 43 34 33 34 35 41 46 44 45 38 41 31 46 44 32 37 33 31 44 39 42 33 36 37 44 36 33 35 33 33 30 32 37 33 45 32 35 46 42 31 44 42 46 44 34 36 38 36 30 38 46 31 35 34 30 34 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidD4CDADA0C4345AFDE8A1FD2731D9B367D635330273E25FB1DBFD468608F15404id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_GB_2147917467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.GB"
        threat_id = "2147917467"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>141C8F13F4B7A4C2EED05A29186AE10F8E849AE4AC2C3E7B167FD27B316E026A</p>" wide //weight: 1
        $x_1_2 = {31 34 31 43 38 46 31 33 46 34 42 37 41 34 43 32 45 45 44 30 35 41 32 39 31 38 36 41 45 31 30 46 38 45 38 34 39 41 45 34 41 43 32 43 33 45 37 42 31 36 37 46 44 32 37 42 33 31 36 45 30 32 36 41 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid141C8F13F4B7A4C2EED05A29186AE10F8E849AE4AC2C3E7B167FD27B316E026Aid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_GC_2147919468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.GC"
        threat_id = "2147919468"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>983E2254D2BDC97E9EE54216C50F12706D3AF0FD6FD19596B676925ECA38FA2C</p>" wide //weight: 1
        $x_1_2 = {39 38 33 45 32 32 35 34 44 32 42 44 43 39 37 45 39 45 45 35 34 32 31 36 43 35 30 46 31 32 37 30 36 44 33 41 46 30 46 44 36 46 44 31 39 35 39 36 42 36 37 36 39 32 35 45 43 41 33 38 46 41 32 43 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid983E2254D2BDC97E9EE54216C50F12706D3AF0FD6FD19596B676925ECA38FA2Cid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_GD_2147919693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.GD"
        threat_id = "2147919693"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>960D9814EFBFC89823219ECCD31B173B1CB9975E181FFD2AF539E09A2CDE7E65</p>" wide //weight: 1
        $x_1_2 = {39 36 30 44 39 38 31 34 45 46 42 46 43 38 39 38 32 33 32 31 39 45 43 43 44 33 31 42 31 37 33 42 31 43 42 39 39 37 35 45 31 38 31 46 46 44 32 41 46 35 33 39 45 30 39 41 32 43 44 45 37 45 36 35 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid960D9814EFBFC89823219ECCD31B173B1CB9975E181FFD2AF539E09A2CDE7E65id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_GE_2147920301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.GE"
        threat_id = "2147920301"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>5700F2F2B10F590AAEEE1C6FA0410CA40A6CD08852B7A1FA26A37A6A06E1A40C</p>" wide //weight: 1
        $x_1_2 = {35 37 30 30 46 32 46 32 42 31 30 46 35 39 30 41 41 45 45 45 31 43 36 46 41 30 34 31 30 43 41 34 30 41 36 43 44 30 38 38 35 32 42 37 41 31 46 41 32 36 41 33 37 41 36 41 30 36 45 31 41 34 30 43 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid5700F2F2B10F590AAEEE1C6FA0410CA40A6CD08852B7A1FA26A37A6A06E1A40Cid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_GF_2147920305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.GF"
        threat_id = "2147920305"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>C2572C8DE4E77D02E8FFC0F9F96FD0F18CCD19C0B6D45E1EA7EFE26203D8DB03</p>" wide //weight: 1
        $x_1_2 = {43 32 35 37 32 43 38 44 45 34 45 37 37 44 30 32 45 38 46 46 43 30 46 39 46 39 36 46 44 30 46 31 38 43 43 44 31 39 43 30 42 36 44 34 35 45 31 45 41 37 45 46 45 32 36 32 30 33 44 38 44 42 30 33 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidC2572C8DE4E77D02E8FFC0F9F96FD0F18CCD19C0B6D45E1EA7EFE26203D8DB03id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_EV_2147920491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.EV"
        threat_id = "2147920491"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>B9B74A412D44C19EEA0343F6146B6C7139221B86390D5597EBE9A2E4FB987A39</p>" wide //weight: 1
        $x_1_2 = {42 39 42 37 34 41 34 31 32 44 34 34 43 31 39 45 45 41 30 33 34 33 46 36 31 34 36 42 36 43 37 31 33 39 32 32 31 42 38 36 33 39 30 44 35 35 39 37 45 42 45 39 41 32 45 34 46 42 39 38 37 41 33 39 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidB9B74A412D44C19EEA0343F6146B6C7139221B86390D5597EBE9A2E4FB987A39id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_GG_2147921811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.GG"
        threat_id = "2147921811"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>DAF390020DB15B4D2822803CC3F4D69EC81D37552B485037261D688F8901665A</p>" wide //weight: 1
        $x_1_2 = {44 41 46 33 39 30 30 32 30 44 42 31 35 42 34 44 32 38 32 32 38 30 33 43 43 33 46 34 44 36 39 45 43 38 31 44 33 37 35 35 32 42 34 38 35 30 33 37 32 36 31 44 36 38 38 46 38 39 30 31 36 36 35 41 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidDAF390020DB15B4D2822803CC3F4D69EC81D37552B485037261D688F8901665Aid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_GH_2147921815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.GH"
        threat_id = "2147921815"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>605399A938178E58CC9CB73F1D9836DAEC173361DBDA1CB98B8C018B2FC23352</p>" wide //weight: 1
        $x_1_2 = {36 30 35 33 39 39 41 39 33 38 31 37 38 45 35 38 43 43 39 43 42 37 33 46 31 44 39 38 33 36 44 41 45 43 31 37 33 33 36 31 44 42 44 41 31 43 42 39 38 42 38 43 30 31 38 42 32 46 43 32 33 33 35 32 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid605399A938178E58CC9CB73F1D9836DAEC173361DBDA1CB98B8C018B2FC23352id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_GI_2147921819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.GI"
        threat_id = "2147921819"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>B093BC843B18EC65A664B83BB7AAE424FE36A17D8520591812D5BA940CC30E45</p>" wide //weight: 1
        $x_1_2 = {42 30 39 33 42 43 38 34 33 42 31 38 45 43 36 35 41 36 36 34 42 38 33 42 42 37 41 41 45 34 32 34 46 45 33 36 41 31 37 44 38 35 32 30 35 39 31 38 31 32 44 35 42 41 39 34 30 43 43 33 30 45 34 35 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidB093BC843B18EC65A664B83BB7AAE424FE36A17D8520591812D5BA940CC30E45id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_GJ_2147921823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.GJ"
        threat_id = "2147921823"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>E230E1322C9C327955926CF965AF386914FA4F67A1516BE93CB7693CE4AC8009</p>" wide //weight: 1
        $x_1_2 = {45 32 33 30 45 31 33 32 32 43 39 43 33 32 37 39 35 35 39 32 36 43 46 39 36 35 41 46 33 38 36 39 31 34 46 41 34 46 36 37 41 31 35 31 36 42 45 39 33 43 42 37 36 39 33 43 45 34 41 43 38 30 30 39 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidE230E1322C9C327955926CF965AF386914FA4F67A1516BE93CB7693CE4AC8009id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_GK_2147921827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.GK"
        threat_id = "2147921827"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>15F496730D19CBF0301FA08BAD9477F04FEEC4AE477C5AC4F164ABC8FC22F71D</p>" wide //weight: 1
        $x_1_2 = {31 35 46 34 39 36 37 33 30 44 31 39 43 42 46 30 33 30 31 46 41 30 38 42 41 44 39 34 37 37 46 30 34 46 45 45 43 34 41 45 34 37 37 43 35 41 43 34 46 31 36 34 41 42 43 38 46 43 32 32 46 37 31 44 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid15F496730D19CBF0301FA08BAD9477F04FEEC4AE477C5AC4F164ABC8FC22F71Did" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_GL_2147921831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.GL"
        threat_id = "2147921831"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>F934F9839465E92E23A755562178404F189D185EDBA96076865713FBD643E95E</p>" wide //weight: 1
        $x_1_2 = {46 39 33 34 46 39 38 33 39 34 36 35 45 39 32 45 32 33 41 37 35 35 35 36 32 31 37 38 34 30 34 46 31 38 39 44 31 38 35 45 44 42 41 39 36 30 37 36 38 36 35 37 31 33 46 42 44 36 34 33 45 39 35 45 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidF934F9839465E92E23A755562178404F189D185EDBA96076865713FBD643E95Eid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_GM_2147922184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.GM"
        threat_id = "2147922184"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>3797455B219CC74EB503399F0E70C57F19FC7BA58A5D36C80264FFA465A4FD21</p>" wide //weight: 1
        $x_1_2 = {33 37 39 37 34 35 35 42 32 31 39 43 43 37 34 45 42 35 30 33 33 39 39 46 30 45 37 30 43 35 37 46 31 39 46 43 37 42 41 35 38 41 35 44 33 36 43 38 30 32 36 34 46 46 41 34 36 35 41 34 46 44 32 31 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid3797455B219CC74EB503399F0E70C57F19FC7BA58A5D36C80264FFA465A4FD21id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_GN_2147923357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.GN"
        threat_id = "2147923357"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>D7A5E0027572764BE600925712D079472FF950F954553FF07E823FF1D068C312</p>" wide //weight: 1
        $x_1_2 = {44 37 41 35 45 30 30 32 37 35 37 32 37 36 34 42 45 36 30 30 39 32 35 37 31 32 44 30 37 39 34 37 32 46 46 39 35 30 46 39 35 34 35 35 33 46 46 30 37 45 38 32 33 46 46 31 44 30 36 38 43 33 31 32 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidD7A5E0027572764BE600925712D079472FF950F954553FF07E823FF1D068C312id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_GO_2147924544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.GO"
        threat_id = "2147924544"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>18EB92BD6E4B55B60CC913088F952B7123D0612A5FCE67C2EDF40AAB687E2904</p>" wide //weight: 1
        $x_1_2 = {31 38 45 42 39 32 42 44 36 45 34 42 35 35 42 36 30 43 43 39 31 33 30 38 38 46 39 35 32 42 37 31 32 33 44 30 36 31 32 41 35 46 43 45 36 37 43 32 45 44 46 34 30 41 41 42 36 38 37 45 32 39 30 34 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid18EB92BD6E4B55B60CC913088F952B7123D0612A5FCE67C2EDF40AAB687E2904id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_GP_2147924548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.GP"
        threat_id = "2147924548"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>8C3995AF7ACD721D8180C19A2C41E7D46C51049BE1871F5784864178BBC18B08</p>" wide //weight: 1
        $x_1_2 = {38 43 33 39 39 35 41 46 37 41 43 44 37 32 31 44 38 31 38 30 43 31 39 41 32 43 34 31 45 37 44 34 36 43 35 31 30 34 39 42 45 31 38 37 31 46 35 37 38 34 38 36 34 31 37 38 42 42 43 31 38 42 30 38 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid8C3995AF7ACD721D8180C19A2C41E7D46C51049BE1871F5784864178BBC18B08id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_GQ_2147924772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.GQ"
        threat_id = "2147924772"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>EF404FB3FC9AC9032A868ED87493D2946D96EFA83DFC6184053CA8289A27FC6C</p>" wide //weight: 1
        $x_1_2 = {45 46 34 30 34 46 42 33 46 43 39 41 43 39 30 33 32 41 38 36 38 45 44 38 37 34 39 33 44 32 39 34 36 44 39 36 45 46 41 38 33 44 46 43 36 31 38 34 30 35 33 43 41 38 32 38 39 41 32 37 46 43 36 43 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidEF404FB3FC9AC9032A868ED87493D2946D96EFA83DFC6184053CA8289A27FC6Cid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_GR_2147924903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.GR"
        threat_id = "2147924903"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>94D11E694A924ECB88D42C2A6412BC980C2744B5FFF784EE6097416C98D97461</p>" wide //weight: 1
        $x_1_2 = {39 34 44 31 31 45 36 39 34 41 39 32 34 45 43 42 38 38 44 34 32 43 32 41 36 34 31 32 42 43 39 38 30 43 32 37 34 34 42 35 46 46 46 37 38 34 45 45 36 30 39 37 34 31 36 43 39 38 44 39 37 34 36 31 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid94D11E694A924ECB88D42C2A6412BC980C2744B5FFF784EE6097416C98D97461id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_GS_2147925089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.GS"
        threat_id = "2147925089"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>14F335E436E62F32720218B99A9DB77EE69AEC3AC8CBEAB0D68CEE67BE89A930</p>" wide //weight: 1
        $x_1_2 = {31 34 46 33 33 35 45 34 33 36 45 36 32 46 33 32 37 32 30 32 31 38 42 39 39 41 39 44 42 37 37 45 45 36 39 41 45 43 33 41 43 38 43 42 45 41 42 30 44 36 38 43 45 45 36 37 42 45 38 39 41 39 33 30 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid14F335E436E62F32720218B99A9DB77EE69AEC3AC8CBEAB0D68CEE67BE89A930id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_GT_2147925705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.GT"
        threat_id = "2147925705"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>28A28E8137979256397197744C175BDAB423B3D05C49E49D2F4C94FE06924310</p>" wide //weight: 1
        $x_1_2 = {32 38 41 32 38 45 38 31 33 37 39 37 39 32 35 36 33 39 37 31 39 37 37 34 34 43 31 37 35 42 44 41 42 34 32 33 42 33 44 30 35 43 34 39 45 34 39 44 32 46 34 43 39 34 46 45 30 36 39 32 34 33 31 30 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid28A28E8137979256397197744C175BDAB423B3D05C49E49D2F4C94FE06924310id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_GU_2147925709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.GU"
        threat_id = "2147925709"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>898923FE0699CFE1EFD17773425DECB080840877C29F883D389D6880B2B96173</p>" wide //weight: 1
        $x_1_2 = {38 39 38 39 32 33 46 45 30 36 39 39 43 46 45 31 45 46 44 31 37 37 37 33 34 32 35 44 45 43 42 30 38 30 38 34 30 38 37 37 43 32 39 46 38 38 33 44 33 38 39 44 36 38 38 30 42 32 42 39 36 31 37 33 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid898923FE0699CFE1EFD17773425DECB080840877C29F883D389D6880B2B96173id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_GV_2147925713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.GV"
        threat_id = "2147925713"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>19A549A57160F384CF4E36EE1A24747ED99C623C48EA545F343296FB7092795D</p>" wide //weight: 1
        $x_1_2 = {31 39 41 35 34 39 41 35 37 31 36 30 46 33 38 34 43 46 34 45 33 36 45 45 31 41 32 34 37 34 37 45 44 39 39 43 36 32 33 43 34 38 45 41 35 34 35 46 33 34 33 32 39 36 46 42 37 30 39 32 37 39 35 44 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid19A549A57160F384CF4E36EE1A24747ED99C623C48EA545F343296FB7092795Did" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_GW_2147926793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.GW"
        threat_id = "2147926793"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>DB6E39D48AEF442A219248F82B2C101FFFCA7DADA77CD9BDE31C886FDECFFB58</p>" wide //weight: 1
        $x_1_2 = {44 42 36 45 33 39 44 34 38 41 45 46 34 34 32 41 32 31 39 32 34 38 46 38 32 42 32 43 31 30 31 46 46 46 43 41 37 44 41 44 41 37 37 43 44 39 42 44 45 33 31 43 38 38 36 46 44 45 43 46 46 42 35 38 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidDB6E39D48AEF442A219248F82B2C101FFFCA7DADA77CD9BDE31C886FDECFFB58id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_GX_2147926994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.GX"
        threat_id = "2147926994"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>D29B43234FD74DC8383AAEA2BDAB5CBE95BA290B930F631E2C65573201A7FD12</p>" wide //weight: 1
        $x_1_2 = {44 32 39 42 34 33 32 33 34 46 44 37 34 44 43 38 33 38 33 41 41 45 41 32 42 44 41 42 35 43 42 45 39 35 42 41 32 39 30 42 39 33 30 46 36 33 31 45 32 43 36 35 35 37 33 32 30 31 41 37 46 44 31 32 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidD29B43234FD74DC8383AAEA2BDAB5CBE95BA290B930F631E2C65573201A7FD12id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_GY_2147928549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.GY"
        threat_id = "2147928549"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>320D6F294A59A1F5AD586599F21058E279929F9D2B4B6C64A3A1789E7FF4C819</p>" wide //weight: 1
        $x_1_2 = {33 32 30 44 36 46 32 39 34 41 35 39 41 31 46 35 41 44 35 38 36 35 39 39 46 32 31 30 35 38 45 32 37 39 39 32 39 46 39 44 32 42 34 42 36 43 36 34 41 33 41 31 37 38 39 45 37 46 46 34 43 38 31 39 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid320D6F294A59A1F5AD586599F21058E279929F9D2B4B6C64A3A1789E7FF4C819id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_GZ_2147929641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.GZ"
        threat_id = "2147929641"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>EAF10F898A86588D593D442A596117983178A7A6ED27882486D7D9C4F8750B3D</p>" wide //weight: 1
        $x_1_2 = {45 41 46 31 30 46 38 39 38 41 38 36 35 38 38 44 35 39 33 44 34 34 32 41 35 39 36 31 31 37 39 38 33 31 37 38 41 37 41 36 45 44 32 37 38 38 32 34 38 36 44 37 44 39 43 34 46 38 37 35 30 42 33 44 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidEAF10F898A86588D593D442A596117983178A7A6ED27882486D7D9C4F8750B3Did" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_HA_2147929740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.HA"
        threat_id = "2147929740"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>AE1C5E273C1B6DDE068DC57B10A7023591C910D1FAAA16E40593D0EEBBD0BE30</p>" wide //weight: 1
        $x_1_2 = {41 45 31 43 35 45 32 37 33 43 31 42 36 44 44 45 30 36 38 44 43 35 37 42 31 30 41 37 30 32 33 35 39 31 43 39 31 30 44 31 46 41 41 41 31 36 45 34 30 35 39 33 44 30 45 45 42 42 44 30 42 45 33 30 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidAE1C5E273C1B6DDE068DC57B10A7023591C910D1FAAA16E40593D0EEBBD0BE30id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_HB_2147930224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.HB"
        threat_id = "2147930224"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>FC5AF6BC0F44FFA33A962DDBB3DECE9115BB2080007A8AA13C6A598237D67F16</p>" wide //weight: 1
        $x_1_2 = {46 43 35 41 46 36 42 43 30 46 34 34 46 46 41 33 33 41 39 36 32 44 44 42 42 33 44 45 43 45 39 31 31 35 42 42 32 30 38 30 30 30 37 41 38 41 41 31 33 43 36 41 35 39 38 32 33 37 44 36 37 46 31 36 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidFC5AF6BC0F44FFA33A962DDBB3DECE9115BB2080007A8AA13C6A598237D67F16id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_HC_2147931627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.HC"
        threat_id = "2147931627"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>20A32ABC1E4EC6D53861D7202E730501EE5E950EB1FE96A0CADB7C231F44C959</p>" wide //weight: 1
        $x_1_2 = {32 30 41 33 32 41 42 43 31 45 34 45 43 36 44 35 33 38 36 31 44 37 32 30 32 45 37 33 30 35 30 31 45 45 35 45 39 35 30 45 42 31 46 45 39 36 41 30 43 41 44 42 37 43 32 33 31 46 34 34 43 39 35 39 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid20A32ABC1E4EC6D53861D7202E730501EE5E950EB1FE96A0CADB7C231F44C959id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_HD_2147931631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.HD"
        threat_id = "2147931631"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>34BA12E4BE532885BAD25BDC4EFA0BCC4145B76B58A90E0C4E2A80D37A5A9F30</p>" wide //weight: 1
        $x_1_2 = {33 34 42 41 31 32 45 34 42 45 35 33 32 38 38 35 42 41 44 32 35 42 44 43 34 45 46 41 30 42 43 43 34 31 34 35 42 37 36 42 35 38 41 39 30 45 30 43 34 45 32 41 38 30 44 33 37 41 35 41 39 46 33 30 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid34BA12E4BE532885BAD25BDC4EFA0BCC4145B76B58A90E0C4E2A80D37A5A9F30id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_HE_2147931635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.HE"
        threat_id = "2147931635"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>D10202E688A76AAFA8B41BADB1354B8EA0CDB1A5CBEBDABDAEE4375509B8E371</p>" wide //weight: 1
        $x_1_2 = {44 31 30 32 30 32 45 36 38 38 41 37 36 41 41 46 41 38 42 34 31 42 41 44 42 31 33 35 34 42 38 45 41 30 43 44 42 31 41 35 43 42 45 42 44 41 42 44 41 45 45 34 33 37 35 35 30 39 42 38 45 33 37 31 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidD10202E688A76AAFA8B41BADB1354B8EA0CDB1A5CBEBDABDAEE4375509B8E371id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_HF_2147931639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.HF"
        threat_id = "2147931639"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>0A79401ECEB69C74FD9831002B97635A13BFDF90C33A83A8EE7014199B1ED05B</p>" wide //weight: 1
        $x_1_2 = {30 41 37 39 34 30 31 45 43 45 42 36 39 43 37 34 46 44 39 38 33 31 30 30 32 42 39 37 36 33 35 41 31 33 42 46 44 46 39 30 43 33 33 41 38 33 41 38 45 45 37 30 31 34 31 39 39 42 31 45 44 30 35 42 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid0A79401ECEB69C74FD9831002B97635A13BFDF90C33A83A8EE7014199B1ED05Bid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_HG_2147931643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.HG"
        threat_id = "2147931643"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>64C2EB66670181B9057E8FD4299032EA89599943E7D36A508CB9DC9CB0513126</p>" wide //weight: 1
        $x_1_2 = {36 34 43 32 45 42 36 36 36 37 30 31 38 31 42 39 30 35 37 45 38 46 44 34 32 39 39 30 33 32 45 41 38 39 35 39 39 39 34 33 45 37 44 33 36 41 35 30 38 43 42 39 44 43 39 43 42 30 35 31 33 31 32 36 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid64C2EB66670181B9057E8FD4299032EA89599943E7D36A508CB9DC9CB0513126id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_HH_2147931647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.HH"
        threat_id = "2147931647"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>AA4D0D135044A1A35A00BF24E453EC93702B5B0279935B9F709E76A155236630</p>" wide //weight: 1
        $x_1_2 = {41 41 34 44 30 44 31 33 35 30 34 34 41 31 41 33 35 41 30 30 42 46 32 34 45 34 35 33 45 43 39 33 37 30 32 42 35 42 30 32 37 39 39 33 35 42 39 46 37 30 39 45 37 36 41 31 35 35 32 33 36 36 33 30 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidAA4D0D135044A1A35A00BF24E453EC93702B5B0279935B9F709E76A155236630id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_HI_2147931651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.HI"
        threat_id = "2147931651"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>D48F8A0B1CE7181EE010FC85EEA0CA92D191A42163A1029C37C04B0BB5A71637</p>" wide //weight: 1
        $x_1_2 = {44 34 38 46 38 41 30 42 31 43 45 37 31 38 31 45 45 30 31 30 46 43 38 35 45 45 41 30 43 41 39 32 44 31 39 31 41 34 32 31 36 33 41 31 30 32 39 43 33 37 43 30 34 42 30 42 42 35 41 37 31 36 33 37 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidD48F8A0B1CE7181EE010FC85EEA0CA92D191A42163A1029C37C04B0BB5A71637id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_HJ_2147931655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.HJ"
        threat_id = "2147931655"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>E4037039EB2D2F52A2B29E783C52FF6FC0E4D29D38611111C19A5E300F82FB0E</p>" wide //weight: 1
        $x_1_2 = {45 34 30 33 37 30 33 39 45 42 32 44 32 46 35 32 41 32 42 32 39 45 37 38 33 43 35 32 46 46 36 46 43 30 45 34 44 32 39 44 33 38 36 31 31 31 31 31 43 31 39 41 35 45 33 30 30 46 38 32 46 42 30 45 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidE4037039EB2D2F52A2B29E783C52FF6FC0E4D29D38611111C19A5E300F82FB0Eid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_HK_2147931833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.HK"
        threat_id = "2147931833"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>07BF3802C93C42739CFD0328A830801C7182C73D2FFC28E76681C6EFFC85A478</p>" wide //weight: 1
        $x_1_2 = {30 37 42 46 33 38 30 32 43 39 33 43 34 32 37 33 39 43 46 44 30 33 32 38 41 38 33 30 38 30 31 43 37 31 38 32 43 37 33 44 32 46 46 43 32 38 45 37 36 36 38 31 43 36 45 46 46 43 38 35 41 34 37 38 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid07BF3802C93C42739CFD0328A830801C7182C73D2FFC28E76681C6EFFC85A478id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_HL_2147931837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.HL"
        threat_id = "2147931837"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>204E91D375BADE81DC528EFCC105A5D046DB92FCC4B75F08E151053DCD8D5025</p>" wide //weight: 1
        $x_1_2 = {32 30 34 45 39 31 44 33 37 35 42 41 44 45 38 31 44 43 35 32 38 45 46 43 43 31 30 35 41 35 44 30 34 36 44 42 39 32 46 43 43 34 42 37 35 46 30 38 45 31 35 31 30 35 33 44 43 44 38 44 35 30 32 35 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid204E91D375BADE81DC528EFCC105A5D046DB92FCC4B75F08E151053DCD8D5025id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_HM_2147931841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.HM"
        threat_id = "2147931841"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>284AFB03BA5BF6D13B3E92B5111E16F5140255075AC0C2775698965895AC5A7D</p>" wide //weight: 1
        $x_1_2 = {32 38 34 41 46 42 30 33 42 41 35 42 46 36 44 31 33 42 33 45 39 32 42 35 31 31 31 45 31 36 46 35 31 34 30 32 35 35 30 37 35 41 43 30 43 32 37 37 35 36 39 38 39 36 35 38 39 35 41 43 35 41 37 44 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid284AFB03BA5BF6D13B3E92B5111E16F5140255075AC0C2775698965895AC5A7Did" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_HN_2147931845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.HN"
        threat_id = "2147931845"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>37070FA85465C92677007577543F09C5B67F8211CCF2C16660D40F94B6847C4A</p>" wide //weight: 1
        $x_1_2 = {33 37 30 37 30 46 41 38 35 34 36 35 43 39 32 36 37 37 30 30 37 35 37 37 35 34 33 46 30 39 43 35 42 36 37 46 38 32 31 31 43 43 46 32 43 31 36 36 36 30 44 34 30 46 39 34 42 36 38 34 37 43 34 41 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid37070FA85465C92677007577543F09C5B67F8211CCF2C16660D40F94B6847C4Aid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_HO_2147931849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.HO"
        threat_id = "2147931849"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>3CC7CCEF369D6A7A4F6CAD11D12D7DE671909962944A7D034282F1F7B54F9D35</p>" wide //weight: 1
        $x_1_2 = {33 43 43 37 43 43 45 46 33 36 39 44 36 41 37 41 34 46 36 43 41 44 31 31 44 31 32 44 37 44 45 36 37 31 39 30 39 39 36 32 39 34 34 41 37 44 30 33 34 32 38 32 46 31 46 37 42 35 34 46 39 44 33 35 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid3CC7CCEF369D6A7A4F6CAD11D12D7DE671909962944A7D034282F1F7B54F9D35id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_HP_2147931853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.HP"
        threat_id = "2147931853"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>57309B4FFB75A04AAAE491451CA128035B78C22AF220F24BDA3CFE0D393ACC18</p>" wide //weight: 1
        $x_1_2 = {35 37 33 30 39 42 34 46 46 42 37 35 41 30 34 41 41 41 45 34 39 31 34 35 31 43 41 31 32 38 30 33 35 42 37 38 43 32 32 41 46 32 32 30 46 32 34 42 44 41 33 43 46 45 30 44 33 39 33 41 43 43 31 38 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid57309B4FFB75A04AAAE491451CA128035B78C22AF220F24BDA3CFE0D393ACC18id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_HQ_2147931857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.HQ"
        threat_id = "2147931857"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>6A301ED6E5D3435A3086C99E892F03DD2322D38737A59AE7B2A0E57FC341D967</p>" wide //weight: 1
        $x_1_2 = {36 41 33 30 31 45 44 36 45 35 44 33 34 33 35 41 33 30 38 36 43 39 39 45 38 39 32 46 30 33 44 44 32 33 32 32 44 33 38 37 33 37 41 35 39 41 45 37 42 32 41 30 45 35 37 46 43 33 34 31 44 39 36 37 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid6A301ED6E5D3435A3086C99E892F03DD2322D38737A59AE7B2A0E57FC341D967id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_HR_2147931861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.HR"
        threat_id = "2147931861"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>6ACB63BA5CE3181B447E9865418497D258550BD88828D460333207EB5BD38D7F</p>" wide //weight: 1
        $x_1_2 = {36 41 43 42 36 33 42 41 35 43 45 33 31 38 31 42 34 34 37 45 39 38 36 35 34 31 38 34 39 37 44 32 35 38 35 35 30 42 44 38 38 38 32 38 44 34 36 30 33 33 33 32 30 37 45 42 35 42 44 33 38 44 37 46 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid6ACB63BA5CE3181B447E9865418497D258550BD88828D460333207EB5BD38D7Fid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_HS_2147931865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.HS"
        threat_id = "2147931865"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>B86FC08132BB71B087740EFA1BE61E3E03117C76E21473F7A4BBAD2FC0FEAA13</p>" wide //weight: 1
        $x_1_2 = {42 38 36 46 43 30 38 31 33 32 42 42 37 31 42 30 38 37 37 34 30 45 46 41 31 42 45 36 31 45 33 45 30 33 31 31 37 43 37 36 45 32 31 34 37 33 46 37 41 34 42 42 41 44 32 46 43 30 46 45 41 41 31 33 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidB86FC08132BB71B087740EFA1BE61E3E03117C76E21473F7A4BBAD2FC0FEAA13id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_HT_2147931869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.HT"
        threat_id = "2147931869"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>E547F7D79733C2C43ACEF824A3208043DEF9F2C372604F662B4BFAEE480FE779</p>" wide //weight: 1
        $x_1_2 = {45 35 34 37 46 37 44 37 39 37 33 33 43 32 43 34 33 41 43 45 46 38 32 34 41 33 32 30 38 30 34 33 44 45 46 39 46 32 43 33 37 32 36 30 34 46 36 36 32 42 34 42 46 41 45 45 34 38 30 46 45 37 37 39 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidE547F7D79733C2C43ACEF824A3208043DEF9F2C372604F662B4BFAEE480FE779id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_HU_2147932099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.HU"
        threat_id = "2147932099"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>061AA6BDE8F6DE6C92F0D6E077359BF6911FCAF80030E82B3A3DB65E63C80113</p>" wide //weight: 1
        $x_1_2 = {30 36 31 41 41 36 42 44 45 38 46 36 44 45 36 43 39 32 46 30 44 36 45 30 37 37 33 35 39 42 46 36 39 31 31 46 43 41 46 38 30 30 33 30 45 38 32 42 33 41 33 44 42 36 35 45 36 33 43 38 30 31 31 33 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid061AA6BDE8F6DE6C92F0D6E077359BF6911FCAF80030E82B3A3DB65E63C80113id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_HV_2147932103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.HV"
        threat_id = "2147932103"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>D671ACD243E7B93732A54D09CCE7A41B59F3D655AA01CB94CFDB3E16A1ACFB02</p>" wide //weight: 1
        $x_1_2 = {44 36 37 31 41 43 44 32 34 33 45 37 42 39 33 37 33 32 41 35 34 44 30 39 43 43 45 37 41 34 31 42 35 39 46 33 44 36 35 35 41 41 30 31 43 42 39 34 43 46 44 42 33 45 31 36 41 31 41 43 46 42 30 32 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidD671ACD243E7B93732A54D09CCE7A41B59F3D655AA01CB94CFDB3E16A1ACFB02id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_HW_2147932107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.HW"
        threat_id = "2147932107"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>E269EA3B12BB0FC371E63700D4458E0465497A67D8B933B3D797454C02AB390C</p>" wide //weight: 1
        $x_1_2 = {45 32 36 39 45 41 33 42 31 32 42 42 30 46 43 33 37 31 45 36 33 37 30 30 44 34 34 35 38 45 30 34 36 35 34 39 37 41 36 37 44 38 42 39 33 33 42 33 44 37 39 37 34 35 34 43 30 32 41 42 33 39 30 43 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidE269EA3B12BB0FC371E63700D4458E0465497A67D8B933B3D797454C02AB390Cid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_HX_2147932111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.HX"
        threat_id = "2147932111"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>6AC5E4FF4999D889C1349A1964F2FCD639FCD4023E4D57673072FB1E6232221C</p>" wide //weight: 1
        $x_1_2 = {36 41 43 35 45 34 46 46 34 39 39 39 44 38 38 39 43 31 33 34 39 41 31 39 36 34 46 32 46 43 44 36 33 39 46 43 44 34 30 32 33 45 34 44 35 37 36 37 33 30 37 32 46 42 31 45 36 32 33 32 32 32 31 43 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid6AC5E4FF4999D889C1349A1964F2FCD639FCD4023E4D57673072FB1E6232221Cid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_HY_2147932115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.HY"
        threat_id = "2147932115"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>7F7CF80A00593E5A789523299A0A1AB6CBFB472EC3A3FD9BFC7B01922A98C30C</p>" wide //weight: 1
        $x_1_2 = {37 46 37 43 46 38 30 41 30 30 35 39 33 45 35 41 37 38 39 35 32 33 32 39 39 41 30 41 31 41 42 36 43 42 46 42 34 37 32 45 43 33 41 33 46 44 39 42 46 43 37 42 30 31 39 32 32 41 39 38 43 33 30 43 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid7F7CF80A00593E5A789523299A0A1AB6CBFB472EC3A3FD9BFC7B01922A98C30Cid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_HZ_2147932539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.HZ"
        threat_id = "2147932539"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>28F633BF7F6E7E5E97726FF65F0A268F219468A35EA14B00F2A728CE66D54D34</p>" wide //weight: 1
        $x_1_2 = {32 38 46 36 33 33 42 46 37 46 36 45 37 45 35 45 39 37 37 32 36 46 46 36 35 46 30 41 32 36 38 46 32 31 39 34 36 38 41 33 35 45 41 31 34 42 30 30 46 32 41 37 32 38 43 45 36 36 44 35 34 44 33 34 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid28F633BF7F6E7E5E97726FF65F0A268F219468A35EA14B00F2A728CE66D54D34id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_IA_2147932543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.IA"
        threat_id = "2147932543"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>6D8560C20E277B28E7C290A678F891F1D2FB32402C0AE80DA18CB2C06F94F644</p>" wide //weight: 1
        $x_1_2 = {36 44 38 35 36 30 43 32 30 45 32 37 37 42 32 38 45 37 43 32 39 30 41 36 37 38 46 38 39 31 46 31 44 32 46 42 33 32 34 30 32 43 30 41 45 38 30 44 41 31 38 43 42 32 43 30 36 46 39 34 46 36 34 34 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid6D8560C20E277B28E7C290A678F891F1D2FB32402C0AE80DA18CB2C06F94F644id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_IB_2147933137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.IB"
        threat_id = "2147933137"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>ADA6E26332F26451E45768179C771CA87A7F0F4E234DA8D882888F505494925D</p>" wide //weight: 1
        $x_1_2 = {41 44 41 36 45 32 36 33 33 32 46 32 36 34 35 31 45 34 35 37 36 38 31 37 39 43 37 37 31 43 41 38 37 41 37 46 30 46 34 45 32 33 34 44 41 38 44 38 38 32 38 38 38 46 35 30 35 34 39 34 39 32 35 44 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidADA6E26332F26451E45768179C771CA87A7F0F4E234DA8D882888F505494925Did" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_IC_2147933141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.IC"
        threat_id = "2147933141"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>D85CCD3DEBA9003CF3083B474976E281F056603C1CE55BC496F5ED88D068606A</p>" wide //weight: 1
        $x_1_2 = {44 38 35 43 43 44 33 44 45 42 41 39 30 30 33 43 46 33 30 38 33 42 34 37 34 39 37 36 45 32 38 31 46 30 35 36 36 30 33 43 31 43 45 35 35 42 43 34 39 36 46 35 45 44 38 38 44 30 36 38 36 30 36 41 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidD85CCD3DEBA9003CF3083B474976E281F056603C1CE55BC496F5ED88D068606Aid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_ID_2147933145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.ID"
        threat_id = "2147933145"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>3BBD6F23D4691C0C7613F9365E947A3CF7F0454CD792364E2A311EF80934C167</p>" wide //weight: 1
        $x_1_2 = {33 42 42 44 36 46 32 33 44 34 36 39 31 43 30 43 37 36 31 33 46 39 33 36 35 45 39 34 37 41 33 43 46 37 46 30 34 35 34 43 44 37 39 32 33 36 34 45 32 41 33 31 31 45 46 38 30 39 33 34 43 31 36 37 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid3BBD6F23D4691C0C7613F9365E947A3CF7F0454CD792364E2A311EF80934C167id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_IE_2147933149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.IE"
        threat_id = "2147933149"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>3F7419E14A3039416E0A226F8D2EDF948A983298DF29A8E9A360CDD089414066</p>" wide //weight: 1
        $x_1_2 = {33 46 37 34 31 39 45 31 34 41 33 30 33 39 34 31 36 45 30 41 32 32 36 46 38 44 32 45 44 46 39 34 38 41 39 38 33 32 39 38 44 46 32 39 41 38 45 39 41 33 36 30 43 44 44 30 38 39 34 31 34 30 36 36 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid3F7419E14A3039416E0A226F8D2EDF948A983298DF29A8E9A360CDD089414066id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_IF_2147933153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.IF"
        threat_id = "2147933153"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>46CA5EEC55A16767B7F8293DB18F753D1BF60C536747EFD115035DDA40948427</p>" wide //weight: 1
        $x_1_2 = {34 36 43 41 35 45 45 43 35 35 41 31 36 37 36 37 42 37 46 38 32 39 33 44 42 31 38 46 37 35 33 44 31 42 46 36 30 43 35 33 36 37 34 37 45 46 44 31 31 35 30 33 35 44 44 41 34 30 39 34 38 34 32 37 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid46CA5EEC55A16767B7F8293DB18F753D1BF60C536747EFD115035DDA40948427id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_IG_2147933157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.IG"
        threat_id = "2147933157"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>620C7A54EC212FB482A684BA74381C3623CCE4D0E27FAE348688F65E0F0F6B6A</p>" wide //weight: 1
        $x_1_2 = {36 32 30 43 37 41 35 34 45 43 32 31 32 46 42 34 38 32 41 36 38 34 42 41 37 34 33 38 31 43 33 36 32 33 43 43 45 34 44 30 45 32 37 46 41 45 33 34 38 36 38 38 46 36 35 45 30 46 30 46 36 42 36 41 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid620C7A54EC212FB482A684BA74381C3623CCE4D0E27FAE348688F65E0F0F6B6Aid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_IH_2147933161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.IH"
        threat_id = "2147933161"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>74773DBD4085BA39A1643CFA561488124771BE839961793DA10245560E1F2D3A</p>" wide //weight: 1
        $x_1_2 = {37 34 37 37 33 44 42 44 34 30 38 35 42 41 33 39 41 31 36 34 33 43 46 41 35 36 31 34 38 38 31 32 34 37 37 31 42 45 38 33 39 39 36 31 37 39 33 44 41 31 30 32 34 35 35 36 30 45 31 46 32 44 33 41 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid74773DBD4085BA39A1643CFA561488124771BE839961793DA10245560E1F2D3Aid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_II_2147933165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.II"
        threat_id = "2147933165"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>90FDB446C1B8D204DE4EE3E393FD636C18798E744A34060C418EF96FD2C37C56</p>" wide //weight: 1
        $x_1_2 = {39 30 46 44 42 34 34 36 43 31 42 38 44 32 30 34 44 45 34 45 45 33 45 33 39 33 46 44 36 33 36 43 31 38 37 39 38 45 37 34 34 41 33 34 30 36 30 43 34 31 38 45 46 39 36 46 44 32 43 33 37 43 35 36 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid90FDB446C1B8D204DE4EE3E393FD636C18798E744A34060C418EF96FD2C37C56id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_IJ_2147933169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.IJ"
        threat_id = "2147933169"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>B053968BBB63D64FE16CFC98AD114E9B2AB85DB5F2D6DA09D31B707868E01005</p>" wide //weight: 1
        $x_1_2 = {42 30 35 33 39 36 38 42 42 42 36 33 44 36 34 46 45 31 36 43 46 43 39 38 41 44 31 31 34 45 39 42 32 41 42 38 35 44 42 35 46 32 44 36 44 41 30 39 44 33 31 42 37 30 37 38 36 38 45 30 31 30 30 35 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidB053968BBB63D64FE16CFC98AD114E9B2AB85DB5F2D6DA09D31B707868E01005id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_IK_2147933173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.IK"
        threat_id = "2147933173"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>BB3DEA31D39FAEF4E3286ED92DF5892E2A5966DAE28468A7BE8B72D54829A60F</p>" wide //weight: 1
        $x_1_2 = {42 42 33 44 45 41 33 31 44 33 39 46 41 45 46 34 45 33 32 38 36 45 44 39 32 44 46 35 38 39 32 45 32 41 35 39 36 36 44 41 45 32 38 34 36 38 41 37 42 45 38 42 37 32 44 35 34 38 32 39 41 36 30 46 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidBB3DEA31D39FAEF4E3286ED92DF5892E2A5966DAE28468A7BE8B72D54829A60Fid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_IL_2147933177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.IL"
        threat_id = "2147933177"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>C1DD64D0994AEAA297225CD94D1A6842819C74319A85350913AB9A82678C001E</p>" wide //weight: 1
        $x_1_2 = {43 31 44 44 36 34 44 30 39 39 34 41 45 41 41 32 39 37 32 32 35 43 44 39 34 44 31 41 36 38 34 32 38 31 39 43 37 34 33 31 39 41 38 35 33 35 30 39 31 33 41 42 39 41 38 32 36 37 38 43 30 30 31 45 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidC1DD64D0994AEAA297225CD94D1A6842819C74319A85350913AB9A82678C001Eid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_IM_2147933181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.IM"
        threat_id = "2147933181"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>E546611D2EFC92779973F7A270ACB77AD325A061B69F5D474608E8F9FFED2803</p>" wide //weight: 1
        $x_1_2 = {45 35 34 36 36 31 31 44 32 45 46 43 39 32 37 37 39 39 37 33 46 37 41 32 37 30 41 43 42 37 37 41 44 33 32 35 41 30 36 31 42 36 39 46 35 44 34 37 34 36 30 38 45 38 46 39 46 46 45 44 32 38 30 33 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidE546611D2EFC92779973F7A270ACB77AD325A061B69F5D474608E8F9FFED2803id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_IN_2147933185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.IN"
        threat_id = "2147933185"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>EC6C1CE4914376904D32257187618E8CC0C5DA6CA98F96FB08E99A75672C1B44</p>" wide //weight: 1
        $x_1_2 = {45 43 36 43 31 43 45 34 39 31 34 33 37 36 39 30 34 44 33 32 32 35 37 31 38 37 36 31 38 45 38 43 43 30 43 35 44 41 36 43 41 39 38 46 39 36 46 42 30 38 45 39 39 41 37 35 36 37 32 43 31 42 34 34 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidEC6C1CE4914376904D32257187618E8CC0C5DA6CA98F96FB08E99A75672C1B44id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_IO_2147933189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.IO"
        threat_id = "2147933189"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>F9342B8E15A0978EC2CEA5A9B9CD43F9110082256195A77F7031A2CEC8E8F871</p>" wide //weight: 1
        $x_1_2 = {46 39 33 34 32 42 38 45 31 35 41 30 39 37 38 45 43 32 43 45 41 35 41 39 42 39 43 44 34 33 46 39 31 31 30 30 38 32 32 35 36 31 39 35 41 37 37 46 37 30 33 31 41 32 43 45 43 38 45 38 46 38 37 31 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidF9342B8E15A0978EC2CEA5A9B9CD43F9110082256195A77F7031A2CEC8E8F871id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_IP_2147933727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.IP"
        threat_id = "2147933727"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>24B03A9DA26336AF573D1DA2D67782C40975A64EFE2E118FE6209049E0F6E655</p>" wide //weight: 1
        $x_1_2 = {32 34 42 30 33 41 39 44 41 32 36 33 33 36 41 46 35 37 33 44 31 44 41 32 44 36 37 37 38 32 43 34 30 39 37 35 41 36 34 45 46 45 32 45 31 31 38 46 45 36 32 30 39 30 34 39 45 30 46 36 45 36 35 35 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid24B03A9DA26336AF573D1DA2D67782C40975A64EFE2E118FE6209049E0F6E655id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_IQ_2147934244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.IQ"
        threat_id = "2147934244"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>EFE31926F41889DBF6588F27A2EC3A2D7DEF7D2E9E0A1DEFD39B976A49C11F0E</p>" wide //weight: 1
        $x_1_2 = {45 46 45 33 31 39 32 36 46 34 31 38 38 39 44 42 46 36 35 38 38 46 32 37 41 32 45 43 33 41 32 44 37 44 45 46 37 44 32 45 39 45 30 41 31 44 45 46 44 33 39 42 39 37 36 41 34 39 43 31 31 46 30 45 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidEFE31926F41889DBF6588F27A2EC3A2D7DEF7D2E9E0A1DEFD39B976A49C11F0Eid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_IR_2147934248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.IR"
        threat_id = "2147934248"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>E83CD54EAAB0F31040D855E1ED993E2AC92652FF8E8742D3901580339D135C6E</p>" wide //weight: 1
        $x_1_2 = {45 38 33 43 44 35 34 45 41 41 42 30 46 33 31 30 34 30 44 38 35 35 45 31 45 44 39 39 33 45 32 41 43 39 32 36 35 32 46 46 38 45 38 37 34 32 44 33 39 30 31 35 38 30 33 33 39 44 31 33 35 43 36 45 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidE83CD54EAAB0F31040D855E1ED993E2AC92652FF8E8742D3901580339D135C6Eid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_IS_2147934368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.IS"
        threat_id = "2147934368"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>9453686EAB63923D1C35C92DDE5E61A6534DD067B5448C1C8D996A460B92CA50</p>" wide //weight: 1
        $x_1_2 = {39 34 35 33 36 38 36 45 41 42 36 33 39 32 33 44 31 43 33 35 43 39 32 44 44 45 35 45 36 31 41 36 35 33 34 44 44 30 36 37 42 35 34 34 38 43 31 43 38 44 39 39 36 41 34 36 30 42 39 32 43 41 35 30 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid9453686EAB63923D1C35C92DDE5E61A6534DD067B5448C1C8D996A460B92CA50id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_IT_2147935786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.IT"
        threat_id = "2147935786"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>FEE914521FB507AB978107ACE3B69B4CA41DA89859408BAE23E1512E8C2E614A</p>" wide //weight: 1
        $x_1_2 = {46 45 45 39 31 34 35 32 31 46 42 35 30 37 41 42 39 37 38 31 30 37 41 43 45 33 42 36 39 42 34 43 41 34 31 44 41 38 39 38 35 39 34 30 38 42 41 45 32 33 45 31 35 31 32 45 38 43 32 45 36 31 34 41 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidFEE914521FB507AB978107ACE3B69B4CA41DA89859408BAE23E1512E8C2E614Aid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_IU_2147935790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.IU"
        threat_id = "2147935790"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>570D7C5DE6B5CDB2D2E9D866C7511301E5566D988B7FA341F30CC3B81A29AE40</p>" wide //weight: 1
        $x_1_2 = {35 37 30 44 37 43 35 44 45 36 42 35 43 44 42 32 44 32 45 39 44 38 36 36 43 37 35 31 31 33 30 31 45 35 35 36 36 44 39 38 38 42 37 46 41 33 34 31 46 33 30 43 43 33 42 38 31 41 32 39 41 45 34 30 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid570D7C5DE6B5CDB2D2E9D866C7511301E5566D988B7FA341F30CC3B81A29AE40id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_IV_2147937410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.IV"
        threat_id = "2147937410"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>0995EB69C04148B6DFBC4775B090834F6E05C36944C6770625984A9A2A2FC23B</p>" wide //weight: 1
        $x_1_2 = {30 39 39 35 45 42 36 39 43 30 34 31 34 38 42 36 44 46 42 43 34 37 37 35 42 30 39 30 38 33 34 46 36 45 30 35 43 33 36 39 34 34 43 36 37 37 30 36 32 35 39 38 34 41 39 41 32 41 32 46 43 32 33 42 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid0995EB69C04148B6DFBC4775B090834F6E05C36944C6770625984A9A2A2FC23Bid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_IW_2147937414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.IW"
        threat_id = "2147937414"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>11D0F394AB8F6F0ECD1321A3743A22D7FC149DB03B505C29B2E541BCC480AF37</p>" wide //weight: 1
        $x_1_2 = {31 31 44 30 46 33 39 34 41 42 38 46 36 46 30 45 43 44 31 33 32 31 41 33 37 34 33 41 32 32 44 37 46 43 31 34 39 44 42 30 33 42 35 30 35 43 32 39 42 32 45 35 34 31 42 43 43 34 38 30 41 46 33 37 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid11D0F394AB8F6F0ECD1321A3743A22D7FC149DB03B505C29B2E541BCC480AF37id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_IX_2147937418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.IX"
        threat_id = "2147937418"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>179ECED0DCE8C07CDFBEA3F290B80B3B6F8BE1500A773F45396CF39183EB5845</p>" wide //weight: 1
        $x_1_2 = {31 37 39 45 43 45 44 30 44 43 45 38 43 30 37 43 44 46 42 45 41 33 46 32 39 30 42 38 30 42 33 42 36 46 38 42 45 31 35 30 30 41 37 37 33 46 34 35 33 39 36 43 46 33 39 31 38 33 45 42 35 38 34 35 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid179ECED0DCE8C07CDFBEA3F290B80B3B6F8BE1500A773F45396CF39183EB5845id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_IY_2147937422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.IY"
        threat_id = "2147937422"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>1EE7194E5F5699163B8B875F272B780FB72FE49C0F21705BF0335698853CC35A</p>" wide //weight: 1
        $x_1_2 = {31 45 45 37 31 39 34 45 35 46 35 36 39 39 31 36 33 42 38 42 38 37 35 46 32 37 32 42 37 38 30 46 42 37 32 46 45 34 39 43 30 46 32 31 37 30 35 42 46 30 33 33 35 36 39 38 38 35 33 43 43 33 35 41 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid1EE7194E5F5699163B8B875F272B780FB72FE49C0F21705BF0335698853CC35Aid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_IZ_2147937426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.IZ"
        threat_id = "2147937426"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>349426AEB4CD3338C9A1AAE88D2F61EA53F0D9E9EB547060D66777CB84CB2702</p>" wide //weight: 1
        $x_1_2 = {33 34 39 34 32 36 41 45 42 34 43 44 33 33 33 38 43 39 41 31 41 41 45 38 38 44 32 46 36 31 45 41 35 33 46 30 44 39 45 39 45 42 35 34 37 30 36 30 44 36 36 37 37 37 43 42 38 34 43 42 32 37 30 32 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid349426AEB4CD3338C9A1AAE88D2F61EA53F0D9E9EB547060D66777CB84CB2702id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_JA_2147937430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.JA"
        threat_id = "2147937430"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>48FC6C22548154CC2C19495A56A69E7FBDB8D3C13EBF4D526BD49746B72E1B4D</p>" wide //weight: 1
        $x_1_2 = {34 38 46 43 36 43 32 32 35 34 38 31 35 34 43 43 32 43 31 39 34 39 35 41 35 36 41 36 39 45 37 46 42 44 42 38 44 33 43 31 33 45 42 46 34 44 35 32 36 42 44 34 39 37 34 36 42 37 32 45 31 42 34 44 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid48FC6C22548154CC2C19495A56A69E7FBDB8D3C13EBF4D526BD49746B72E1B4Did" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_JB_2147937434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.JB"
        threat_id = "2147937434"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>4BA82D3C2DEEC79996BF9B06BD91B5C98BB11F6D3B1E269668B2FAC1F538BA65</p>" wide //weight: 1
        $x_1_2 = {34 42 41 38 32 44 33 43 32 44 45 45 43 37 39 39 39 36 42 46 39 42 30 36 42 44 39 31 42 35 43 39 38 42 42 31 31 46 36 44 33 42 31 45 32 36 39 36 36 38 42 32 46 41 43 31 46 35 33 38 42 41 36 35 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid4BA82D3C2DEEC79996BF9B06BD91B5C98BB11F6D3B1E269668B2FAC1F538BA65id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_JC_2147937438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.JC"
        threat_id = "2147937438"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>7D514FF4BADC574BE0C71DD2D01370F3377CBE820BBDE79A6F0A0D46C4F8D75C</p>" wide //weight: 1
        $x_1_2 = {37 44 35 31 34 46 46 34 42 41 44 43 35 37 34 42 45 30 43 37 31 44 44 32 44 30 31 33 37 30 46 33 33 37 37 43 42 45 38 32 30 42 42 44 45 37 39 41 36 46 30 41 30 44 34 36 43 34 46 38 44 37 35 43 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid7D514FF4BADC574BE0C71DD2D01370F3377CBE820BBDE79A6F0A0D46C4F8D75Cid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_JD_2147937442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.JD"
        threat_id = "2147937442"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>7DA3575AC5D57B3B5B93914DEF1E87AAD80319C2F5779F68B53A329AD7C1DE45</p>" wide //weight: 1
        $x_1_2 = {37 44 41 33 35 37 35 41 43 35 44 35 37 42 33 42 35 42 39 33 39 31 34 44 45 46 31 45 38 37 41 41 44 38 30 33 31 39 43 32 46 35 37 37 39 46 36 38 42 35 33 41 33 32 39 41 44 37 43 31 44 45 34 35 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid7DA3575AC5D57B3B5B93914DEF1E87AAD80319C2F5779F68B53A329AD7C1DE45id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_JE_2147937446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.JE"
        threat_id = "2147937446"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>A990C13C53C7C926595A144AC3C3919C64CF2CBE300F77EA969383ED785BCD22</p>" wide //weight: 1
        $x_1_2 = {41 39 39 30 43 31 33 43 35 33 43 37 43 39 32 36 35 39 35 41 31 34 34 41 43 33 43 33 39 31 39 43 36 34 43 46 32 43 42 45 33 30 30 46 37 37 45 41 39 36 39 33 38 33 45 44 37 38 35 42 43 44 32 32 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidA990C13C53C7C926595A144AC3C3919C64CF2CBE300F77EA969383ED785BCD22id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_JF_2147937450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.JF"
        threat_id = "2147937450"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>CE1604BCC1D5B7543AFAB646518363E926F33EA97F5DA5C77CDAF38633A25E43</p>" wide //weight: 1
        $x_1_2 = {43 45 31 36 30 34 42 43 43 31 44 35 42 37 35 34 33 41 46 41 42 36 34 36 35 31 38 33 36 33 45 39 32 36 46 33 33 45 41 39 37 46 35 44 41 35 43 37 37 43 44 41 46 33 38 36 33 33 41 32 35 45 34 33 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidCE1604BCC1D5B7543AFAB646518363E926F33EA97F5DA5C77CDAF38633A25E43id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_JG_2147937454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.JG"
        threat_id = "2147937454"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>CF62DD142C7FBC8E79ECB16973DA572E918D6A8D69B4E163A91EFF91A0D0674B</p>" wide //weight: 1
        $x_1_2 = {43 46 36 32 44 44 31 34 32 43 37 46 42 43 38 45 37 39 45 43 42 31 36 39 37 33 44 41 35 37 32 45 39 31 38 44 36 41 38 44 36 39 42 34 45 31 36 33 41 39 31 45 46 46 39 31 41 30 44 30 36 37 34 42 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidCF62DD142C7FBC8E79ECB16973DA572E918D6A8D69B4E163A91EFF91A0D0674Bid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_JH_2147937458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.JH"
        threat_id = "2147937458"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>D2CA90BD5028C4DDE223E20674062AD45C6629D666FBFC9C4ECDCE2493700069</p>" wide //weight: 1
        $x_1_2 = {44 32 43 41 39 30 42 44 35 30 32 38 43 34 44 44 45 32 32 33 45 32 30 36 37 34 30 36 32 41 44 34 35 43 36 36 32 39 44 36 36 36 46 42 46 43 39 43 34 45 43 44 43 45 32 34 39 33 37 30 30 30 36 39 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidD2CA90BD5028C4DDE223E20674062AD45C6629D666FBFC9C4ECDCE2493700069id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_JI_2147937462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.JI"
        threat_id = "2147937462"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>F7FACEB9D3F06F8A45896C03A7D88B5D3090CEE38D3EF908BCDE83BC65E2CA30</p>" wide //weight: 1
        $x_1_2 = {46 37 46 41 43 45 42 39 44 33 46 30 36 46 38 41 34 35 38 39 36 43 30 33 41 37 44 38 38 42 35 44 33 30 39 30 43 45 45 33 38 44 33 45 46 39 30 38 42 43 44 45 38 33 42 43 36 35 45 32 43 41 33 30 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidF7FACEB9D3F06F8A45896C03A7D88B5D3090CEE38D3EF908BCDE83BC65E2CA30id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_JJ_2147937466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.JJ"
        threat_id = "2147937466"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>FB9B2B31E76E2672AE7F14F3F394B3064529B5762B329F602C422D0D75009E6A</p>" wide //weight: 1
        $x_1_2 = {46 42 39 42 32 42 33 31 45 37 36 45 32 36 37 32 41 45 37 46 31 34 46 33 46 33 39 34 42 33 30 36 34 35 32 39 42 35 37 36 32 42 33 32 39 46 36 30 32 43 34 32 32 44 30 44 37 35 30 30 39 45 36 41 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidFB9B2B31E76E2672AE7F14F3F394B3064529B5762B329F602C422D0D75009E6Aid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_JK_2147937470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.JK"
        threat_id = "2147937470"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>FD38D64D730DFD46889E569AE6BB2681431692BD7FB038EFECA7E8B044CF511E</p>" wide //weight: 1
        $x_1_2 = {46 44 33 38 44 36 34 44 37 33 30 44 46 44 34 36 38 38 39 45 35 36 39 41 45 36 42 42 32 36 38 31 34 33 31 36 39 32 42 44 37 46 42 30 33 38 45 46 45 43 41 37 45 38 42 30 34 34 43 46 35 31 31 45 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidFD38D64D730DFD46889E569AE6BB2681431692BD7FB038EFECA7E8B044CF511Eid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_JL_2147939915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.JL"
        threat_id = "2147939915"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>0C8E5B45C57AE244E9C904C5BC74F73306937469D9CEA22541CA69AC162B8D42</p>" wide //weight: 1
        $x_1_2 = {30 43 38 45 35 42 34 35 43 35 37 41 45 32 34 34 45 39 43 39 30 34 43 35 42 43 37 34 46 37 33 33 30 36 39 33 37 34 36 39 44 39 43 45 41 32 32 35 34 31 43 41 36 39 41 43 31 36 32 42 38 44 34 32 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid0C8E5B45C57AE244E9C904C5BC74F73306937469D9CEA22541CA69AC162B8D42id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_JM_2147940259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.JM"
        threat_id = "2147940259"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>E8481B6E149862EEEA79668EBBC50B96A6B6529C5DDD905491E2F838EF7D174F</p>" wide //weight: 1
        $x_1_2 = {45 38 34 38 31 42 36 45 31 34 39 38 36 32 45 45 45 41 37 39 36 36 38 45 42 42 43 35 30 42 39 36 41 36 42 36 35 32 39 43 35 44 44 44 39 30 35 34 39 31 45 32 46 38 33 38 45 46 37 44 31 37 34 46 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidE8481B6E149862EEEA79668EBBC50B96A6B6529C5DDD905491E2F838EF7D174Fid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_JN_2147942772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.JN"
        threat_id = "2147942772"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>9D97F166730F865F793E2EA07B173C742A6302879DE1B0BBB03817A5A04B572F</p>" wide //weight: 1
        $x_1_2 = {39 44 39 37 46 31 36 36 37 33 30 46 38 36 35 46 37 39 33 45 32 45 41 30 37 42 31 37 33 43 37 34 32 41 36 33 30 32 38 37 39 44 45 31 42 30 42 42 42 30 33 38 31 37 41 35 41 30 34 42 35 37 32 46 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid9D97F166730F865F793E2EA07B173C742A6302879DE1B0BBB03817A5A04B572Fid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_JO_2147942967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.JO"
        threat_id = "2147942967"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>BBF77F0461AEE151529EC77FBFD38D5818AAED1DC6A9E6AD65D96717453B7921</p>" wide //weight: 1
        $x_1_2 = {42 42 46 37 37 46 30 34 36 31 41 45 45 31 35 31 35 32 39 45 43 37 37 46 42 46 44 33 38 44 35 38 31 38 41 41 45 44 31 44 43 36 41 39 45 36 41 44 36 35 44 39 36 37 31 37 34 35 33 42 37 39 32 31 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidBBF77F0461AEE151529EC77FBFD38D5818AAED1DC6A9E6AD65D96717453B7921id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_JP_2147942971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.JP"
        threat_id = "2147942971"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>644D8416E1695DC98593DFB5E55CF50F209327665D28655164511E2482D0F80B</p>" wide //weight: 1
        $x_1_2 = {36 34 34 44 38 34 31 36 45 31 36 39 35 44 43 39 38 35 39 33 44 46 42 35 45 35 35 43 46 35 30 46 32 30 39 33 32 37 36 36 35 44 32 38 36 35 35 31 36 34 35 31 31 45 32 34 38 32 44 30 46 38 30 42 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid644D8416E1695DC98593DFB5E55CF50F209327665D28655164511E2482D0F80Bid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_JQ_2147942975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.JQ"
        threat_id = "2147942975"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>AF9C4725A434490923A9F4C32B5F9003ED77428AD82AF86E757120F743A96D28</p>" wide //weight: 1
        $x_1_2 = {41 46 39 43 34 37 32 35 41 34 33 34 34 39 30 39 32 33 41 39 46 34 43 33 32 42 35 46 39 30 30 33 45 44 37 37 34 32 38 41 44 38 32 41 46 38 36 45 37 35 37 31 32 30 46 37 34 33 41 39 36 44 32 38 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidAF9C4725A434490923A9F4C32B5F9003ED77428AD82AF86E757120F743A96D28id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_JR_2147944076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.JR"
        threat_id = "2147944076"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>DC9D709BD034A7CC6BE02E58E1159B724FB4A75BBDD47D53CFF86724A60BB223</p>" wide //weight: 1
        $x_1_2 = {44 43 39 44 37 30 39 42 44 30 33 34 41 37 43 43 36 42 45 30 32 45 35 38 45 31 31 35 39 42 37 32 34 46 42 34 41 37 35 42 42 44 44 34 37 44 35 33 43 46 46 38 36 37 32 34 41 36 30 42 42 32 32 33 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidDC9D709BD034A7CC6BE02E58E1159B724FB4A75BBDD47D53CFF86724A60BB223id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_JS_2147944573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.JS"
        threat_id = "2147944573"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>457BB4E5DF0E650509322CA894758D925A568828090A3449D5AEEED30E9B8E18</p>" wide //weight: 1
        $x_1_2 = {34 35 37 42 42 34 45 35 44 46 30 45 36 35 30 35 30 39 33 32 32 43 41 38 39 34 37 35 38 44 39 32 35 41 35 36 38 38 32 38 30 39 30 41 33 34 34 39 44 35 41 45 45 45 44 33 30 45 39 42 38 45 31 38 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid457BB4E5DF0E650509322CA894758D925A568828090A3449D5AEEED30E9B8E18id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_JT_2147945164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.JT"
        threat_id = "2147945164"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>AFD02E37CDA7D994F7E91FE7ACE71DE2E88F5C49233D3EFAB3210554629A6E5E</p>" wide //weight: 1
        $x_1_2 = {41 46 44 30 32 45 33 37 43 44 41 37 44 39 39 34 46 37 45 39 31 46 45 37 41 43 45 37 31 44 45 32 45 38 38 46 35 43 34 39 32 33 33 44 33 45 46 41 42 33 32 31 30 35 35 34 36 32 39 41 36 45 35 45 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidAFD02E37CDA7D994F7E91FE7ACE71DE2E88F5C49233D3EFAB3210554629A6E5Eid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_JU_2147945801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.JU"
        threat_id = "2147945801"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>BFC836EBAE06450FDD36B63170F121F44ADADFF2DAFAAFA41314B6778F600350</p>" wide //weight: 1
        $x_1_2 = {42 46 43 38 33 36 45 42 41 45 30 36 34 35 30 46 44 44 33 36 42 36 33 31 37 30 46 31 32 31 46 34 34 41 44 41 44 46 46 32 44 41 46 41 41 46 41 34 31 33 31 34 42 36 37 37 38 46 36 30 30 33 35 30 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidBFC836EBAE06450FDD36B63170F121F44ADADFF2DAFAAFA41314B6778F600350id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_JV_2147945805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.JV"
        threat_id = "2147945805"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>EC99BD5A36DE69144F5402C832B5413295323FC7C12259C53E4AA6D5BC2D4E6D</p>" wide //weight: 1
        $x_1_2 = {45 43 39 39 42 44 35 41 33 36 44 45 36 39 31 34 34 46 35 34 30 32 43 38 33 32 42 35 34 31 33 32 39 35 33 32 33 46 43 37 43 31 32 32 35 39 43 35 33 45 34 41 41 36 44 35 42 43 32 44 34 45 36 44 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidEC99BD5A36DE69144F5402C832B5413295323FC7C12259C53E4AA6D5BC2D4E6Did" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_JW_2147946175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.JW"
        threat_id = "2147946175"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>50FA856FE57D6A299A738A0D1E19E69EAF2C5409D617919580242BACAFC88A1D</p>" wide //weight: 1
        $x_1_2 = {35 30 46 41 38 35 36 46 45 35 37 44 36 41 32 39 39 41 37 33 38 41 30 44 31 45 31 39 45 36 39 45 41 46 32 43 35 34 30 39 44 36 31 37 39 31 39 35 38 30 32 34 32 42 41 43 41 46 43 38 38 41 31 44 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid50FA856FE57D6A299A738A0D1E19E69EAF2C5409D617919580242BACAFC88A1Did" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_JX_2147946257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.JX"
        threat_id = "2147946257"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>6A340207246B47E37F6D094D2236E5C6242B6E4461EEF8021FED2C9855240C3E</p>" wide //weight: 1
        $x_1_2 = {36 41 33 34 30 32 30 37 32 34 36 42 34 37 45 33 37 46 36 44 30 39 34 44 32 32 33 36 45 35 43 36 32 34 32 42 36 45 34 34 36 31 45 45 46 38 30 32 31 46 45 44 32 43 39 38 35 35 32 34 30 43 33 45 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid6A340207246B47E37F6D094D2236E5C6242B6E4461EEF8021FED2C9855240C3Eid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_JY_2147946443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.JY"
        threat_id = "2147946443"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>535F403A2EA2DC71A392E18D7DB77FEF70845C0B7E5B9114CD30D30187030437</p>" wide //weight: 1
        $x_1_2 = {35 33 35 46 34 30 33 41 32 45 41 32 44 43 37 31 41 33 39 32 45 31 38 44 37 44 42 37 37 46 45 46 37 30 38 34 35 43 30 42 37 45 35 42 39 31 31 34 43 44 33 30 44 33 30 31 38 37 30 33 30 34 33 37 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid535F403A2EA2DC71A392E18D7DB77FEF70845C0B7E5B9114CD30D30187030437id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_JZ_2147946503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.JZ"
        threat_id = "2147946503"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>B26253E0A8F87CBBA29519E7295397631326D94162D29F9A2B1CAE6899791210</p>" wide //weight: 1
        $x_1_2 = {42 32 36 32 35 33 45 30 41 38 46 38 37 43 42 42 41 32 39 35 31 39 45 37 32 39 35 33 39 37 36 33 31 33 32 36 44 39 34 31 36 32 44 32 39 46 39 41 32 42 31 43 41 45 36 38 39 39 37 39 31 32 31 30 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableidB26253E0A8F87CBBA29519E7295397631326D94162D29F9A2B1CAE6899791210id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AbuseCommBack_KA_2147946507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AbuseCommBack.KA"
        threat_id = "2147946507"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AbuseCommBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<p>23B35DB9AC6DEFD7F2EF445F3F8B1DB1B046756605110AC7C73AF90ED7952B5A</p>" wide //weight: 1
        $x_1_2 = {32 33 42 33 35 44 42 39 41 43 36 44 45 46 44 37 46 32 45 46 34 34 35 46 33 46 38 42 31 44 42 31 42 30 34 36 37 35 36 36 30 35 31 31 30 41 43 37 43 37 33 41 46 39 30 45 44 37 39 35 32 42 35 41 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "tableid23B35DB9AC6DEFD7F2EF445F3F8B1DB1B046756605110AC7C73AF90ED7952B5Aid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

