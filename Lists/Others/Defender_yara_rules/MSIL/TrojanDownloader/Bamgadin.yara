rule TrojanDownloader_MSIL_Bamgadin_2147696086_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Bamgadin"
        threat_id = "2147696086"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bamgadin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "baglanmadi" wide //weight: 3
        $x_3_2 = "http://212.129.31.67" wide //weight: 3
        $x_3_3 = "ejder*" wide //weight: 3
        $x_3_4 = {74 42 69 72 69 6e 63 69 4f 72 67 61 6e 69 6b 5f 54 69 63 6b 00}  //weight: 3, accuracy: High
        $x_3_5 = {74 53 69 74 65 67 65 7a 5f 54 69 63 6b 00}  //weight: 3, accuracy: High
        $x_1_6 = "/C choice /C Y /N /D Y /T 3 & Del" wide //weight: 1
        $x_1_7 = "/c start  \"calistir\"" wide //weight: 1
        $x_1_8 = "/c attrib +s +h" wide //weight: 1
        $x_2_9 = "\\Windows.zip" wide //weight: 2
        $x_2_10 = "\\System.zip" wide //weight: 2
        $x_2_11 = "Initial Catalog=organikhit; User ID=ronaldo;" wide //weight: 2
        $x_2_12 = "exec uyepckontrol @mac, @pc, @s" wide //weight: 2
        $x_1_13 = {2e 00 36 00 37 00 2f 00 [0-16] 76 00 65 00 72 00 73 00 69 00 79 00 6f 00 6e 00 2e 00 74 00 78 00 74 00}  //weight: 1, accuracy: Low
        $x_1_14 = {73 00 63 00 2e 00 65 00 78 00 65 00 [0-4] 73 00 76 00 63 00 68 00 6f 00 73 00 74 00}  //weight: 1, accuracy: Low
        $x_1_15 = {61 00 75 00 74 00 6f 00 [0-4] 7b 00 30 00 7d 00 20 00 7b 00 31 00 7d 00 20 00 [0-4] 43 00 72 00 65 00 61 00 74 00 65 00 [0-4] 62 00 69 00 6e 00 50 00 61 00 74 00 68 00 3d 00 20 00 22 00 7b 00 30 00 7d 00 22 00 20 00 20 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            ((1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Bamgadin_A_2147707248_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Bamgadin.A"
        threat_id = "2147707248"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bamgadin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {50 72 6f 6a 65 63 74 49 6e 73 74 61 6c 6c 65 72 00 73 76 63 68 6f 73 74 00 49 6e 73 74 61 6c 6c 65 72 00 53 79 73 74 65 6d 2e 43 6f 6e 66 69 67 75 72 61 74 69 6f 6e 2e 49 6e 73 74 61 6c 6c}  //weight: 2, accuracy: High
        $x_2_2 = {73 65 72 76 69 63 65 2e 65 78 65 00 3c 4d 6f 64 75 6c 65 3e}  //weight: 2, accuracy: High
        $x_1_3 = {73 65 74 5f 41 63 63 6f 75 6e 74 00 53 65 72 76 69 63 65 41 63 63 6f 75 6e 74}  //weight: 1, accuracy: High
        $x_1_4 = {73 65 74 5f 50 61 73 73 77 6f 72 64 00 73 65 74 5f 55 73 65 72 6e 61 6d 65}  //weight: 1, accuracy: High
        $x_1_5 = {73 65 74 5f 53 65 72 76 69 63 65 4e 61 6d 65 00 73 65 74 5f 53 74 61 72 74 54 79 70 65 00 53 65 72 76 69 63 65 53 74 61 72 74 4d 6f 64 65}  //weight: 1, accuracy: High
        $x_1_6 = {73 65 74 5f 43 72 65 61 74 65 4e 6f 57 69 6e 64 6f 77 00 73 65 74 5f 57 69 6e 64 6f 77 53 74 79 6c 65}  //weight: 1, accuracy: High
        $x_1_7 = "svchost.ProjectInstaller.resources" ascii //weight: 1
        $x_1_8 = "selcuk@globaltech.com.tr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

