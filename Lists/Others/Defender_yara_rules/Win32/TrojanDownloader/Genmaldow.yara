rule TrojanDownloader_Win32_Genmaldow_A_2147708719_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Genmaldow.A!bit"
        threat_id = "2147708719"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Genmaldow"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 43 6d 64 20 46 69 6c 65 73 5c [0-16] 2e 70 6e 67}  //weight: 1, accuracy: Low
        $x_1_2 = {69 6d 67 2e 73 79 75 61 6e 2e 6e 65 74 2f 66 6f 72 75 6d 2f [0-64] 2e 6a 70 67}  //weight: 1, accuracy: Low
        $x_1_3 = "MyAppByMulinB" ascii //weight: 1
        $x_1_4 = "ExeProcesstest" ascii //weight: 1
        $x_1_5 = "server.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

