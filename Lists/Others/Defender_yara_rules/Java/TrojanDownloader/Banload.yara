rule TrojanDownloader_Java_Banload_Q_2147716854_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Java/Banload.Q"
        threat_id = "2147716854"
        type = "TrojanDownloader"
        platform = "Java: Java binaries (classes)"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "?directDownload=true" ascii //weight: 1
        $x_1_2 = "https://www.sugarsync.com/pf" ascii //weight: 1
        $x_1_3 = "!C:\\Windows\\System32\\Rundll32.exe" ascii //weight: 1
        $x_1_4 = "Bang.java" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Java_Banload_Q_2147716854_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Java/Banload.Q"
        threat_id = "2147716854"
        type = "TrojanDownloader"
        platform = "Java: Java binaries (classes)"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 44 33 32 33 33 38 32 37 5f 37 37 35 5f 32 35 33 38 32 [0-8] 3f 64 69 72 65 63 74 44 6f 77 6e 6c 6f 61 64 3d 74 72 75 65}  //weight: 1, accuracy: Low
        $x_1_2 = "Firma_iniciando/Transporte" ascii //weight: 1
        $x_1_3 = "https://www.sugarsync.com/pf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Java_Banload_R_2147716911_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Java/Banload.R"
        threat_id = "2147716911"
        type = "TrojanDownloader"
        platform = "Java: Java binaries (classes)"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 71 75 69 72 72 65 6c 31 32 33 ?? 00}  //weight: 2, accuracy: Low
        $x_1_2 = {44 45 53 01 00 ?? 0f 00 2e 65 78 65 01 00 [0-31] 53 79 6e 54 50 45 6e 68 53 65 72 76 69 63 65 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = {2f 52 61 6e 64 6f 6d [0-5] 67 65 72 61 64 61}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 63 6f 6d (2e|2f) 6d 6f 64 [0-9] 2f 6d 6f 64 [0-9] (31|32 2e) 64 61 74 [0-159] 2e 63 6f 6d (2e|2f) 6d 6f 64 [0-9] 2f 6d 6f 64 0f 00 2e 64 61 74}  //weight: 1, accuracy: Low
        $x_2_5 = {68 74 74 70 3a 2f 2f 34 35 2e [0-47] 2e 64 61 74 [0-15] 68 74 74 70 3a 2f 2f 34 35 2e [0-47] 32 2e 64 61 74}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Java_Banload_W_2147724251_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Java/Banload.W"
        threat_id = "2147724251"
        type = "TrojanDownloader"
        platform = "Java: Java binaries (classes)"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Administrador\\teste.zip" ascii //weight: 1
        $x_1_2 = ".zip?attredirects=0&d=1" ascii //weight: 1
        $x_1_3 = "\\crypts.dll,Certeza" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Java_Banload_X_2147725174_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Java/Banload.X!bit"
        threat_id = "2147725174"
        type = "TrojanDownloader"
        platform = "Java: Java binaries (classes)"
        family = "Banload"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f 4c 6c 6f 61 64 65 72 2f 4c 6f 61 64 65 72}  //weight: 10, accuracy: High
        $x_10_2 = "a3A5BD69FA19005BB2.zip" ascii //weight: 10
        $x_1_3 = {08 44 6f 77 6e 6c 6f 61 64}  //weight: 1, accuracy: High
        $x_1_4 = {08 65 78 74 72 61 74 6f 72}  //weight: 1, accuracy: High
        $x_1_5 = {07 65 78 65 63 75 74 65}  //weight: 1, accuracy: High
        $x_1_6 = {06 64 65 6c 65 74 65}  //weight: 1, accuracy: High
        $x_1_7 = {63 6d 64 2e 65 78 65 20 2f [0-16] 6c 6f 63 61 6c 61 70 70 64 61 74 61 [0-48] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Java_Banload_GA_2147756696_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Java/Banload.GA!MTB"
        threat_id = "2147756696"
        type = "TrojanDownloader"
        platform = "Java: Java binaries (classes)"
        family = "Banload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "www.sugarsync.com/pf/" ascii //weight: 1
        $x_1_2 = "Users\\Public\\an.jar" ascii //weight: 1
        $x_1_3 = "?directDownload=true" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

