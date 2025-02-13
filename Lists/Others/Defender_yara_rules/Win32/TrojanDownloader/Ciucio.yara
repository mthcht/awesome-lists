rule TrojanDownloader_Win32_Ciucio_C_2147639990_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Ciucio.C"
        threat_id = "2147639990"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Ciucio"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = ":\\Dropbox\\My Dropbox\\Projetos\\javan\\start\\" ascii //weight: 10
        $x_1_2 = "DllUnregisterServer" ascii //weight: 1
        $x_1_3 = {5c 54 45 4d 50 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 5c 54 4d 50 00}  //weight: 1, accuracy: Low
        $x_1_4 = "Wship6.dll" ascii //weight: 1
        $x_1_5 = "SVCHOST" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

