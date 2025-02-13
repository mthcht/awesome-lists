rule TrojanDownloader_Win32_Allsum_2147804049_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Allsum"
        threat_id = "2147804049"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Allsum"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Microsoft Visual C++ Runtime Library" ascii //weight: 1
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "ccmd://PopupAD" ascii //weight: 1
        $x_1_4 = "Explorer\\Browser Helper Objects\\{0E674588-66B7-4E19-9D0E-2053B800F69F}" ascii //weight: 1
        $x_1_5 = "CreateAcceleratorTableA" ascii //weight: 1
        $x_1_6 = "DestroyAcceleratorTable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Allsum_2147804049_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Allsum"
        threat_id = "2147804049"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Allsum"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {2e 64 6c 6c 00 51 75 65 72 79 50 6c 75 67 69 6e 00 00 00}  //weight: 10, accuracy: High
        $x_1_2 = "d:\\work\\cfs2.me\\cfs2\\src\\main\\" ascii //weight: 1
        $x_1_3 = "eventadclick" ascii //weight: 1
        $x_1_4 = {68 74 74 70 3a 2f 2f 00 32 30 32 2e 31 30 34 2e 31 31 2e 39 34}  //weight: 1, accuracy: High
        $x_1_5 = "SHOW AD Plugin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Allsum_2147804049_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Allsum"
        threat_id = "2147804049"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Allsum"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Microsoft Visual C++ Runtime Library" ascii //weight: 10
        $x_1_2 = "8A4280AD-9B37-4922-A51D-73F3C3A32AF7" ascii //weight: 1
        $x_1_3 = "63e3925a-fe0e-49b8-afe3-d0f19d19a0cd" ascii //weight: 1
        $x_10_4 = "ourxin.com/cfs" ascii //weight: 10
        $x_10_5 = "InternetOpenUrlA" ascii //weight: 10
        $x_10_6 = "GetLastActivePopup" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Allsum_2147804049_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Allsum"
        threat_id = "2147804049"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Allsum"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "%sspoolsv.exe -printer" ascii //weight: 4
        $x_2_2 = "?guid=%s&vendor=%s&os=%u" ascii //weight: 2
        $x_2_3 = "\\Config\\plugins.ini" ascii //weight: 2
        $x_2_4 = "\\wmpdrm.dll" ascii //weight: 2
        $x_3_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects\\{0E674588-66B7-4E19-9D0E-2053B800F69F}" ascii //weight: 3
        $x_2_6 = "10 min checking..." ascii //weight: 2
        $x_2_7 = "cause event %s..." ascii //weight: 2
        $x_2_8 = "plugincall_plugin_liveupdate_checkwebpage" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_4_*) and 5 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

