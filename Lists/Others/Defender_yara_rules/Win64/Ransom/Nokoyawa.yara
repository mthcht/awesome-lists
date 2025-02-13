rule Ransom_Win64_Nokoyawa_AA_2147818738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Nokoyawa.AA"
        threat_id = "2147818738"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Nokoyawa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_5_2 = {3d 7c c4 8c 7c}  //weight: 5, accuracy: High
        $x_5_3 = {3d 89 28 f0 d6}  //weight: 5, accuracy: High
        $x_5_4 = {3d 15 b7 7b c2}  //weight: 5, accuracy: High
        $x_5_5 = {3d 26 b4 80 7c}  //weight: 5, accuracy: High
        $x_5_6 = {3d b5 99 f2 11}  //weight: 5, accuracy: High
        $x_5_7 = {3d 95 39 fb 78}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Nokoyawa_AD_2147818751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Nokoyawa.AD!MTB"
        threat_id = "2147818751"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Nokoyawa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 04 00 00 00 48 6b c0 ?? b9 04 00 00 00 48 6b c9 ?? 8b 4c 0c 20 8b 44 04 20 33 c1 b9 04 00 00 00 48 6b c9 ?? 33 44 0c 20 b9 04 00 00 00 48 6b c9 ?? 33 44 0c 20 89 04 24 8b 04 24 d1 e0 8b 0c 24 c1 e9 1f 0b c1}  //weight: 1, accuracy: Low
        $x_1_2 = {89 84 24 74 01 00 00 48 8b 84 24 c0 01 00 00 8b 8c 24 74 01 00 00 89 48 0c 8b 84 24 74 01 00 00 89 44 24 10 48 8b 84 24 c0 01 00 00 8b 4c 24 14 8b 40 10 03 c1 89 84 24 78 01 00 00 48 8b 84 24 c0 01 00 00 8b 8c 24 78 01 00 00 89 48 10 8b 84 24 78 01 00 00 89 44 24 14 e9 ?? ?? ff ff 48 81 c4 a8 01 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = "Encrypt only selected file" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Nokoyawa_A_2147818790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Nokoyawa.A"
        threat_id = "2147818790"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Nokoyawa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4e 4f 4b 4f 59 41 57 41 2e 65 78 ?? 20 28 45 6e 63 72 79 70 74 20 61 6c 6c 20 6c 6f 63 61 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Nokoyawa_AB_2147819960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Nokoyawa.AB"
        threat_id = "2147819960"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Nokoyawa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {80 00 00 00 c7 44 24 20 03 00 00 00 45 33 c9 41 b8 03 00 00 00 ba 9f 01 12 00 48 8b 8c ?? ?? ?? ?? ?? ff 15}  //weight: 10, accuracy: Low
        $x_10_3 = {41 b9 18 00 00 00 4c 8d 44 ?? ?? ba 28 c0 53 00 48 8b 4c ?? ?? ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Nokoyawa_AC_2147819961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Nokoyawa.AC"
        threat_id = "2147819961"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Nokoyawa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {48 83 ec 28 48 83 3d ?? ?? ?? ?? 00 75 14 48 8d 0d ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 48 83 3d ?? ?? ?? ?? 00 75 1b 48 8d 15 ?? ?? ?? ?? 48 8b 0d ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 41 b9 02 00 00 00 44 8b 44 24 ?? 48 8b 54 24 ?? 33 c9 ff 15 ?? ?? ?? ?? 48 83 c4 28}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Nokoyawa_BA_2147827076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Nokoyawa.BA"
        threat_id = "2147827076"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Nokoyawa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8b c2 4d 8d 40 ?? 33 c2 81 c2 ?? ?? ?? ?? 69 c8 ?? ?? ?? ?? 81 f1 ?? ?? ?? ?? 8b c1 c1 e8 0d 33 c1 69 c8 ?? ?? ?? ?? 8b c1 c1 e8 0f 33 c1 41 89 40 fc 49 83 e9 01 75}  //weight: 1, accuracy: Low
        $x_1_2 = "NOKOYAWA v2.0.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Nokoyawa_AL_2147840944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Nokoyawa.AL!MTB"
        threat_id = "2147840944"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Nokoyawa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8b c4 41 83 c4 01 49 83 c0 01 99 83 e2 0f 03 c2 83 e0 0f 2b c2 48 63 c8 48 8b 44 ?? ?? 42 0f b6 8c 31 ?? ?? ?? ?? 41 32 4c 00 ff 43 88 4c 18 ff 44 3b 64 ?? ?? 41 8b c4 41 83 c4 01 49 83 c0 01 99}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Nokoyawa_AM_2147840953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Nokoyawa.AM!MTB"
        threat_id = "2147840953"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Nokoyawa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Users\\user\\Desktop\\new\\noko\\target\\release\\deps\\noko.pdb" ascii //weight: 1
        $x_1_2 = "RUST_BACKTRACE=full" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Nokoyawa_AN_2147840954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Nokoyawa.AN!MTB"
        threat_id = "2147840954"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Nokoyawa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ENCRYPT_NETWORK" ascii //weight: 1
        $x_1_2 = "LOAD_HIDDEN_DRIVES" ascii //weight: 1
        $x_1_3 = "DELETE_SHADOW" ascii //weight: 1
        $x_1_4 = "nokonoko" wide //weight: 1
        $x_1_5 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\nokonoko" wide //weight: 1
        $x_1_6 = "/set {default} safeboot network" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

