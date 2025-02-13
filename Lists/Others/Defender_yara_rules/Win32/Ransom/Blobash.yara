rule Ransom_Win32_Blobash_A_2147690504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Blobash.A"
        threat_id = "2147690504"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Blobash"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "WinRAR\\Rar.exe\" a -r -y -ri15 -df -m0 -inul -p%pass% %filename%" ascii //weight: 10
        $x_10_2 = "WinRAR\\Rar.exe\" c %filename% -z%commentsfile%" ascii //weight: 10
        $x_10_3 = "Lock.rar" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

