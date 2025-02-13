rule PWS_Win32_Smiwil_A_2147629862_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Smiwil.A"
        threat_id = "2147629862"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Smiwil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "csrss.exe /shtml" ascii //weight: 1
        $x_1_2 = "iexplore.exe /shtml" ascii //weight: 1
        $x_1_3 = "services.exe /shtml" ascii //weight: 1
        $x_1_4 = "spoolsv.exe /shtml" ascii //weight: 1
        $x_1_5 = "%computername%-Chrome.html" ascii //weight: 1
        $x_1_6 = "%computername%-IE.html" ascii //weight: 1
        $x_1_7 = "%computername%-Storage.html" ascii //weight: 1
        $x_1_8 = "%computername%-Firefox.html" ascii //weight: 1
        $x_2_9 = "user smiwil7>" ascii //weight: 2
        $x_2_10 = "getwindowpos>>" ascii //weight: 2
        $x_2_11 = {66 74 70 20 2d 6e 20 2d 73 3a 74 65 6d 70 [0-4] 2e 72 61 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

