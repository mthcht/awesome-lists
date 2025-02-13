rule TrojanDownloader_Win32_Metkicrp_A_2147728051_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Metkicrp.A!bit"
        threat_id = "2147728051"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Metkicrp"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "$URL = _BASE64DECODE ( \"aHR0cHM6Ly9maWxlcy5" wide //weight: 1
        $x_1_2 = {24 00 45 00 58 00 45 00 20 00 3d 00 20 00 22 00 73 00 65 00 72 00 76 00 65 00 72 00 [0-16] 2e 00 65 00 78 00 65 00 22 00}  //weight: 1, accuracy: Low
        $x_1_3 = "INETGET ( $URL , $DIR & $EXE )" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

