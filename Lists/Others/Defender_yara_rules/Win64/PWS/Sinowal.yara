rule PWS_Win64_Sinowal_A_2147659341_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win64/Sinowal.gen!A"
        threat_id = "2147659341"
        type = "PWS"
        platform = "Win64: Windows 64-bit platform"
        family = "Sinowal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 69 48 8b 44 24 20 0f be 00 83 c8 60 89 44 24 08 48 c7 04 24 01 00 00 00 eb 0c 48 8b 04 24 48 83 c0 01}  //weight: 1, accuracy: High
        $x_1_2 = {49 63 46 3c 42 81 3c 30 50 45 00 00 0f 85 ?? ?? ?? ?? 66 42 81 7c 30 18 0b 02 0f 85}  //weight: 1, accuracy: Low
        $x_1_3 = {49 8b 4d 20 49 8b 45 18 4c 89 1c c8 49 83 45 20 01 41 81 3c bc 18 05 e5 54}  //weight: 1, accuracy: High
        $x_1_4 = "&itag=ody&q=%s%%2C%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule PWS_Win64_Sinowal_B_2147659658_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win64/Sinowal.gen!B"
        threat_id = "2147659658"
        type = "PWS"
        platform = "Win64: Windows 64-bit platform"
        family = "Sinowal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8d 44 24 28 48 8b e1 48 8b 28 48 8b 70 08 48 8b 78 10 48 8b 58 18 41 50 52 48 83 ec ?? 48 c7 c2 01 00 00 00 49 8b c9 48 81 e1 00 00 ff ff 41 ff d1 48 83 c4 ?? 5a 41 58 48 8b ca 48 c7 c2 00 00 00 00 49 8b c0 49 c7 c0 00 80 00 00 49 c7 c1 00 00 00 00 ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win64_Sinowal_C_2147682025_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win64/Sinowal.gen!C"
        threat_id = "2147682025"
        type = "PWS"
        platform = "Win64: Windows 64-bit platform"
        family = "Sinowal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8d 44 24 28 48 8b e1 48 8b 58 18 48 8b 70 08 48 8b 28 48 8b 78 10 41 50 52 48 83 ec ?? 48 33 d2 48 ff c2 49 8b c9 48 81 e1 00 00 ff ff 41 ff d1 48 83 c4 ?? 5a 41 58 48 8b ca 48 c7 c2 00 00 00 00 4d 8b d0 49 c7 c1 00 00 00 00 49 c7 c0 00 80 00 00 41 ff e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win64_Sinowal_D_2147682140_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win64/Sinowal.gen!D"
        threat_id = "2147682140"
        type = "PWS"
        platform = "Win64: Windows 64-bit platform"
        family = "Sinowal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b8 f6 04 f1 4d 41 8b d4 48 8b cf e8 ?? ?? ?? ?? 4c 8d ?? ?? ?? ?? ?? 41 b8 da 05 2d 08 41 8b d4 48 8b cf}  //weight: 1, accuracy: Low
        $x_1_2 = {66 90 66 66 90 66 83 7a 48 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

