rule TrojanDownloader_Java_OpenStream_A_2147654236_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Java/OpenStream.gen!A"
        threat_id = "2147654236"
        type = "TrojanDownloader"
        platform = "Java: Java binaries (classes)"
        family = "OpenStream"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "!(Lcom/ms/security/PermissionID;)V" ascii //weight: 1
        $x_1_2 = "()Ljava/net/URLConnection;" ascii //weight: 1
        $x_1_3 = "ERROR_EXELOADER" ascii //weight: 1
        $x_1_4 = "Matrix.java" ascii //weight: 1
        $x_1_5 = "com/ms/win32/Kernel32" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Java_OpenStream_A_2147654236_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Java/OpenStream.gen!A"
        threat_id = "2147654236"
        type = "TrojanDownloader"
        platform = "Java: Java binaries (classes)"
        family = "OpenStream"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 61 70 70 65 6e 64 01 00 2d 28 4c 6a 61 76 61 2f 6c 61 6e 67 2f 53 74 72 69 6e 67 3b 29 4c 6a 61 76 61 2f 6c 61 6e 67 2f 53 74 72 69 6e 67 42 75 69 6c 64 65 72 3b 01 00 08 74 6f 53 74 72 69 6e 67 01}  //weight: 1, accuracy: High
        $x_1_2 = {0e 6f 70 65 6e 43 6f 6e 6e 65 63 74 69 6f 6e 01 00 1a 28 29 4c 6a 61 76 61 2f 6e 65 74 2f 55 52 4c 43 6f 6e 6e 65 63 74 69 6f 6e 3b 01 00 0e 67 65 74 49 6e 70 75 74 53 74 72 65 61 6d 01 00 17 28 29 4c 6a 61 76 61 2f 69 6f 2f 49 6e 70 75 74 53 74 72 65 61 6d 3b 01 00 04 72 65 61 64 01 00 07 28 5b 42 49 49 29 49 01 00 05 77 72 69 74 65 01 00 07 28 5b 42 49 49 29 56 01 00 05 63 6c 6f 73 65 01}  //weight: 1, accuracy: High
        $x_1_3 = {11 6a 61 76 61 2f 6c 61 6e 67 2f 52 75 6e 74 69 6d 65 01 00 0a 67 65 74 52 75 6e 74 69 6d 65 01 00 15 28 29 4c 6a 61 76 61 2f 6c 61 6e 67 2f 52 75 6e 74 69 6d 65 3b 01 00 04 65 78 65 63 01}  //weight: 1, accuracy: High
        $x_1_4 = {11 04 00 bc 08 3a ?? 19 ?? 19 ?? 03 19 ?? be b6 00 ?? 59 36 ?? 02 9f 00 ?? (2d|19 ??) 19 ?? 03 15 ?? b6 00 ?? a7 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Java_OpenStream_BL_2147655256_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Java/OpenStream.BL"
        threat_id = "2147655256"
        type = "TrojanDownloader"
        platform = "Java: Java binaries (classes)"
        family = "OpenStream"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 00 20 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f ?? 71 72 73 74 75 76 77 78 79 7a 3a 2f 2e 3d 26 2d}  //weight: 10, accuracy: Low
        $x_10_2 = {06 5b 5e 30 2d 39 5d}  //weight: 10, accuracy: High
        $x_1_3 = {01 00 10 30 ?? 31 35 ?? ?? ?? ?? ?? ?? ?? ?? 31 39 ?? 30}  //weight: 1, accuracy: Low
        $x_1_4 = {01 00 12 34 ?? 32 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? 38 31 ?? 34 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Java_OpenStream_BK_2147655257_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Java/OpenStream.BK"
        threat_id = "2147655257"
        type = "TrojanDownloader"
        platform = "Java: Java binaries (classes)"
        family = "OpenStream"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 04 00 bc 08 [0-48] 02 9f 00 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? a7 ff e4}  //weight: 1, accuracy: Low
        $x_1_2 = {6e 65 74 2f 55 52 4c [0-24] 59 6f 75 72 44 69 72 65 63 74 4c 69 6e}  //weight: 1, accuracy: Low
        $x_1_3 = "YourFile" ascii //weight: 1
        $x_1_4 = {01 00 04 47 6f 54 6f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Java_OpenStream_BY_2147658890_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Java/OpenStream.BY"
        threat_id = "2147658890"
        type = "TrojanDownloader"
        platform = "Java: Java binaries (classes)"
        family = "OpenStream"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "regsvr32 -s \"" ascii //weight: 1
        $x_1_2 = "openStream" ascii //weight: 1
        $x_1_3 = "va.io.tmpdir" ascii //weight: 1
        $x_1_4 = "exec" ascii //weight: 1
        $x_1_5 = "setSecurityManager" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

