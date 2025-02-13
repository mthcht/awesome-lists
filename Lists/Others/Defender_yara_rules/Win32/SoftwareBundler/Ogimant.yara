rule SoftwareBundler_Win32_Ogimant_225375_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Ogimant"
        threat_id = "225375"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Ogimant"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 2f 66 6f 72 63 65 73 2e 73 75 6e 73 68 69 6e 65 62 6c 6f 67 2e 72 75 2f 67 65 74 5f 6a 73 6f 6e 3f 73 74 62 3d 34 26 64 69 64 3d ?? ?? ?? ?? ?? ?? ?? (30|31|32|33|34|35|36|37|38|39) (30|31|32|33|34|35|36|37|38|39) 26 65 78 74 5f 70 61 72 74 6e 65 72 5f 69 64 3d 26 66 69 6c 65 5f 69 64 3d ?? ?? ?? ?? ?? ?? ?? (30|31|32|33|34|35|36|37|38|39) (30|31|32|33|34|35|36|37|38|39)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule SoftwareBundler_Win32_Ogimant_225375_1
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Ogimant"
        threat_id = "225375"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Ogimant"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%s.%d.exe" ascii //weight: 1
        $x_1_2 = "partner_new_url" ascii //weight: 1
        $x_1_3 = {42 49 4e 00 72 75 6e 70 72 6f 67 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_4 = "downloader_tmp_" ascii //weight: 1
        $x_1_5 = {89 45 e0 8b 45 e0 0f b6 00 3c 3f}  //weight: 1, accuracy: High
        $x_1_6 = {2f 76 65 72 79 73 69 6c 65 6e 74 [0-5] 75 72 6c 3d}  //weight: 1, accuracy: Low
        $x_1_7 = "force_run" ascii //weight: 1
        $x_1_8 = {26 69 6e 66 6f 3d 00}  //weight: 1, accuracy: High
        $x_1_9 = {26 73 74 61 67 65 3d 00}  //weight: 1, accuracy: High
        $x_1_10 = {26 63 6f 64 65 3d 00}  //weight: 1, accuracy: High
        $x_1_11 = {26 68 65 61 64 65 72 73 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule SoftwareBundler_Win32_Ogimant_225375_2
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Ogimant"
        threat_id = "225375"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Ogimant"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 5a d0 80 fb 09 77 1b 8d 04 80 0f be d2 8d 44 42 d0 0f b6 11 83 c1 01 84 d2 75 e4 eb 05}  //weight: 1, accuracy: High
        $x_1_2 = {29 c2 8b 0d ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 32 0c 03 88 4c 16 ff 83 e8 01 83 f8 ff 75 dd}  //weight: 1, accuracy: Low
        $x_1_3 = {29 c1 8b 1d ?? ?? ?? ?? 32 1c 02 88 5c 0e ff 83 e8 01 83 f8 ff 75 e3}  //weight: 1, accuracy: Low
        $x_1_4 = {0f b6 55 e7 31 ca 88 10}  //weight: 1, accuracy: High
        $x_1_5 = {0f b6 45 e7 31 d0 88 03}  //weight: 1, accuracy: High
        $x_1_6 = {8b 50 28 8b 45 ?? 85 d2 74 ?? 03 55 ?? 74 ?? c7 44 24 08 00 00 00 00 c7 44 24 04 01 00 00 00 8b 4d ?? 89 0c 24 ff d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule SoftwareBundler_Win32_Ogimant_225375_3
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Ogimant"
        threat_id = "225375"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Ogimant"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "mailruhomesearch.exe" ascii //weight: 1
        $x_1_2 = {44 6f 77 6e 6c 6f 61 64 65 72 [0-16] 4d 4c 52}  //weight: 1, accuracy: Low
        $x_1_3 = "%s.%d.exe" ascii //weight: 1
        $x_1_4 = "profitraf" ascii //weight: 1
        $x_1_5 = "--partner_new_url" ascii //weight: 1
        $x_1_6 = {42 49 4e 00 72 75 6e 70 72 6f 67 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_7 = "downloader_tmp_" ascii //weight: 1
        $x_1_8 = {89 45 e0 8b 45 e0 0f b6 00 3c 3f}  //weight: 1, accuracy: High
        $x_1_9 = "mailrusputnik.exe" ascii //weight: 1
        $x_1_10 = "/silent /rfr=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule SoftwareBundler_Win32_Ogimant_225375_4
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Ogimant"
        threat_id = "225375"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Ogimant"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://product.mobogenie.com/pc/clientDownload.htm" ascii //weight: 1
        $x_1_2 = "http://sputnikmailru.cdnmail.ru/mailruhomesearch.exe" ascii //weight: 1
        $x_1_3 = "http://amigobin.cdnmail.ru/AmigoDistrib.exe" ascii //weight: 1
        $x_1_4 = {68 20 bf 02 00 e8 e2 9b 17 00 66 c7 43 10 18 00 8d 45 fc e8 90 ff ff ff 50 ff 43 1c ba 31 d2 57 00 8d 45 f0 e8 7b 93 17 00 ff 43 1c 8b 00 5a e8 bc 8e 17 00 ff 4b 1c 8d 45 f0 ba 02 00 00 00 e8 7c 94 17 00 66 c7 43 10 0c 00 66 c7 43 10 24 00 8d 45 f8 e8 50 ff ff ff 50 ff 43 1c ba 36 d2 57 00 8d 45 ec e8 3b 93 17 00}  //weight: 1, accuracy: High
        $x_1_5 = "((http|https)://|www\\.)youtube.com/watch\\?.*\\&?v=[a-z,A-Z,0-9,_,-" ascii //weight: 1
        $x_1_6 = "ping=instpaid&bundle=%addonkey%&s=%success%&wmid=%wmid%&progid=mi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

