rule TrojanDownloader_Win32_Enameler_B_2147825967_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Enameler.B!dha"
        threat_id = "2147825967"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Enameler"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "svchosts.exe" ascii //weight: 1
        $x_1_2 = "/files/index.php?" ascii //weight: 1
        $x_1_3 = "ENAMELIB" ascii //weight: 1
        $x_1_4 = "gname" ascii //weight: 1
        $x_1_5 = "msdtcpwe.dat" ascii //weight: 1
        $x_1_6 = "html<''K(*" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Enameler_C_2147825970_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Enameler.C!dha"
        threat_id = "2147825970"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Enameler"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ENAMELIB001.dll" ascii //weight: 1
        $x_1_2 = "getlog" ascii //weight: 1
        $x_1_3 = "8du7hv76)(*HUY%^TR$EpW<:>HUijkso" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

