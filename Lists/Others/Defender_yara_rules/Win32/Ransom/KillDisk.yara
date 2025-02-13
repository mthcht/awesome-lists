rule Ransom_Win32_KillDisk_PA_2147816802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/KillDisk.PA!MTB"
        threat_id = "2147816802"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "KillDisk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {73 79 73 74 65 6d 33 32 5c 63 6d 64 2e 65 78 65 [0-16] 73 68 75 74 64 6f 77 6e 20 2f 72 20 2f 74 20 25 64 [0-16] 2f 63 20 64 65 6c 20 2f 46 20 2f 53 20 2f 51 20 25 63 3a 5c 2a 2e 2a}  //weight: 5, accuracy: Low
        $x_1_2 = ".exe.sys.drv.doc.docx.xls.xlsx.mdb.ppt.pptx.xml.jpg" wide //weight: 1
        $x_1_3 = "Software\\MicrosoftSecurity" wide //weight: 1
        $x_1_4 = "/c format %c: /Y /X /FS:NTFS" ascii //weight: 1
        $x_1_5 = "\\\\.\\PhysicalDrive%d" wide //weight: 1
        $x_1_6 = "msDefenderSvc" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

