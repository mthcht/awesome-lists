rule TrojanDownloader_Win32_PSWSteal_A_2147728045_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/PSWSteal.A!bit"
        threat_id = "2147728045"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "PSWSteal"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "URLDownloadToFile" ascii //weight: 1
        $x_1_2 = {68 74 74 70 73 3a 2f 2f 63 68 65 63 6b 61 6e 64 73 77 69 74 63 68 2e 63 6f 6d 2f 61 66 69 6c 65 2f [0-32] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_PSWSteal_B_2147728212_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/PSWSteal.B!bit"
        threat_id = "2147728212"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "PSWSteal"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://u.to/PbrTEg" ascii //weight: 1
        $x_1_2 = "URLDownloadToFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_PSWSteal_D_2147729974_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/PSWSteal.D!bit"
        threat_id = "2147729974"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "PSWSteal"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "URLDownloadToFile, https://goo.gl/" ascii //weight: 1
        $x_1_2 = "RegWrite, REG_SZ, HKCU\\TigerTrade" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

