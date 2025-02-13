rule TrojanDownloader_Win32_Nitedrem_A_2147679110_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Nitedrem.A"
        threat_id = "2147679110"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Nitedrem"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 0d 00 00 ff ff 40 3d ff 7f 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {05 01 80 ff ff 33 d2 85 c0 0f 9f c2 f7 da 89}  //weight: 1, accuracy: High
        $x_1_3 = {05 01 80 ff ff 85 c0 0f 9f c2 f7 da 89}  //weight: 1, accuracy: High
        $x_2_4 = "6C5157422D1B5946330A5956375C575B7E5C5646375454596540" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Nitedrem_D_2147687838_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Nitedrem.D"
        threat_id = "2147687838"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Nitedrem"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bucks.onepiecedream.com" wide //weight: 1
        $x_1_2 = "/down.asp?action=install&u=" wide //weight: 1
        $x_1_3 = "/down.asp?action=down&u=" wide //weight: 1
        $x_1_4 = "User-Agent: fucking" wide //weight: 1
        $x_1_5 = "iamruningstartgaga" wide //weight: 1
        $x_1_6 = "iminfornexyinggagahhjkashd" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_Win32_Nitedrem_E_2147694713_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Nitedrem.E"
        threat_id = "2147694713"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Nitedrem"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/down.asp?action=install&u=" wide //weight: 1
        $x_1_2 = {00 00 66 00 75 00 63 00 6b 00 69 00 6e 00 67 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = ".cloudfront.net/ppi2.exe" wide //weight: 1
        $x_1_4 = {00 00 30 00 33 00 38 00 35 00 42 00 31 00 36 00 39 00 42 00 34 00 46 00 42 00 34 00 36 00 44 00 46 00 39 00 33 00 41 00 31 00 34 00 41 00 46 00 33 00 39 00 46 00 34 00 35 00 46 00 34 00 30 00 42 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Nitedrem_F_2147712467_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Nitedrem.F!bit"
        threat_id = "2147712467"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Nitedrem"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 00 61 00 69 00 6e 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 2e 00 65 00 78 00 65 00 00 00 5a 00 00 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 00 66 00 75 00 63 00 6b 00 69 00 6e 00 67 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "/down.asp?action=newinstall&u=" wide //weight: 1
        $x_1_4 = {00 00 37 00 45 00 37 00 30 00 37 00 32 00 30 00 32 00 42 00 31 00 35 00 39 00 34 00 41 00 37 00 42 00 42 00 46 00 44 00 30 00 45 00 32 00 42 00 45 00 45 00 41 00 46 00 41 00 41 00 37 00 30 00 33 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 00 30 00 33 00 38 00 35 00 42 00 31 00 36 00 39 00 42 00 34 00 46 00 42 00 34 00 36 00 44 00 46 00 39 00 33 00 41 00 31 00 34 00 41 00 46 00 33 00 39 00 46 00 34 00 35 00 46 00 34 00 30 00 42 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {2e 00 63 00 6c 00 6f 00 75 00 64 00 66 00 72 00 6f 00 6e 00 74 00 2e 00 6e 00 65 00 74 00 2f 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

