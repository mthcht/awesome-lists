rule TrojanDownloader_Win32_Mukeralmoh_STA_2147784131_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Mukeralmoh.STA"
        threat_id = "2147784131"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Mukeralmoh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {78 6c 41 75 74 6f 4f 70 65 6e 00}  //weight: 2, accuracy: High
        $x_1_2 = "zhomla.com" wide //weight: 1
        $x_1_3 = "%PUBLIC%\\soundlib64.exe" wide //weight: 1
        $x_1_4 = "/database_client2.xml" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Mukeralmoh_STB_2147784132_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Mukeralmoh.STB"
        threat_id = "2147784132"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Mukeralmoh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {78 6c 41 75 74 6f 4f 70 65 6e 00}  //weight: 2, accuracy: High
        $x_1_2 = "flickr.com.auditblogs.com" wide //weight: 1
        $x_1_3 = "applib.hta" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Mukeralmoh_STC_2147784133_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Mukeralmoh.STC"
        threat_id = "2147784133"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Mukeralmoh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {78 6c 41 75 74 6f 4f 70 65 6e 00}  //weight: 2, accuracy: High
        $x_1_2 = "srand04rf.ru" wide //weight: 1
        $x_1_3 = "%PUBLIC%\\res32.hta" wide //weight: 1
        $x_1_4 = "/92375234.xml" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

