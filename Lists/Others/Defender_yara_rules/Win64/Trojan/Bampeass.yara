rule Trojan_Win64_Bampeass_A_2147696407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bampeass.A"
        threat_id = "2147696407"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bampeass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[UCM] Wusa failed copy Hibiki" wide //weight: 1
        $x_1_2 = "%temp%\\Hibiki.dll" wide //weight: 1
        $x_1_3 = "Elevation:Administrator!new:{4D111E08-CBF7-4f12-A926-2C7920AF52FC}" wide //weight: 1
        $x_1_4 = "UACMe injected, Fubuki at your service" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bampeass_B_2147696408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bampeass.B"
        threat_id = "2147696408"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bampeass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UACMe injected, Hibiki at your service." ascii //weight: 1
        $x_1_2 = "ucmLoadCallback, dll load %ws, DllBase = %p" ascii //weight: 1
        $x_2_3 = {ba 63 00 00 00 48 2b f8 90 0f b7 4c 07 02 48 8d 40 02 0f b7 d1 66 85 c9 75 ef 48 8d 44 24 70 48 8d 0d a3 1c 00 00 45 33 c9 48 89 44 24 48 48 8d 45 90 45 33 c0 48 89 44 24 40 48 8d 45 00 33 d2 48 89 44 24 38 48 89 5c 24 30 89 5c 24 28 89 5c 24 20 ff 15}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Bampeass_C_2147706309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bampeass.C"
        threat_id = "2147706309"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bampeass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 75 63 6d 4c 6f 61 64 43 61 6c 6c 62 61 63 6b 2c 20 64 6c 6c 20 6c 6f 61 64 20 25 77 73 2c 20 44 6c 6c 42 61 73 65 20 3d 20 25 70 0a 0d 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 55 41 43 4d 65 20 69 6e 6a 65 63 74 65 64 2c 20 48 69 62 69 6b 69 20 61 74 20 79 6f 75 72 20 73 65 72 76 69 63 65 2e 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 75 63 6d 4c 6f 61 64 43 61 6c 6c 62 61 63 6b 2c 20 6b 65 72 6e 65 6c 33 32 20 62 61 73 65 20 66 6f 75 6e 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

