rule TrojanDownloader_Win32_Choziosi_A_2147809950_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Choziosi.A"
        threat_id = "2147809950"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Choziosi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ChromeLoader" wide //weight: 2
        $x_2_2 = "/c start /min \"\" powershell -ExecutionPolicy Bypass -WindowStyle Hidden -E" wide //weight: 2
        $x_2_3 = "JABlAHgAdABQAGEAdABoACAAPQAgACIA" wide //weight: 2
        $x_2_4 = "\\CS_installer.pdb" ascii //weight: 2
        $x_1_5 = "_meta.txt" wide //weight: 1
        $x_1_6 = "deScramble" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Choziosi_VS_2147819690_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Choziosi.VS!MSR"
        threat_id = "2147819690"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Choziosi"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CS_installer.exe" ascii //weight: 2
        $x_2_2 = "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -E" wide //weight: 2
        $x_1_3 = "_meta.txt" wide //weight: 1
        $x_1_4 = "deScramble" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

