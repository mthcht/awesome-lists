rule TrojanDownloader_Win32_Ainslot_DAA_2147748643_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Ainslot.DAA!MTB"
        threat_id = "2147748643"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Ainslot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "xenservice.exe" ascii //weight: 1
        $x_1_2 = "qemu-ga.exe" ascii //weight: 1
        $x_2_3 = "cmd.exe /c start /B powershell -windowstyle hidden -command \"&{$t='#i#ex####@(n#ew###-#ob#jec#t N#####et#.W#eb#Cl#ie#nt#).#Up#loa#d#####St#ri#ng" ascii //weight: 2
        $x_2_4 = {28 23 27 27 68 23 74 23 74 70 23 3a 23 2f 2f [0-64] 2f 6c 65 67 23 69 6f 6e 31 23 37 23 2f 23 77 23 65 6c 23 63 6f 23 6d 65 27 27 23 2c 23 27 27 48 23 6f 72 23 73 65 48 6f 23 75 72 73 27 27 23 29 23 7c 23 69 23 65 23 78 27 2e 72 65 70 6c 61 63 65 28 27 23 27 2c 27 27 29 2e 73 70 6c 69 74 28 27 40 27 2c 35 29 3b 26}  //weight: 2, accuracy: Low
        $x_2_5 = {68 74 74 70 3a 2f 2f [0-15] 75 70 64 61 74 65 32 2e [0-5] 2f 74 65 73 74 2f 75 73 2f [0-15] 2e 65 78 65}  //weight: 2, accuracy: Low
        $x_1_6 = "\\pool.exe" ascii //weight: 1
        $x_1_7 = "\\paster.exe" ascii //weight: 1
        $x_1_8 = "\\uc.exe" ascii //weight: 1
        $x_1_9 = "\\postrtretbacks.exe" ascii //weight: 1
        $x_1_10 = "\\neerterva.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

