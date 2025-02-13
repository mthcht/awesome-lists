rule Ransom_Win32_Contentocrypt_A_2147719969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Contentocrypt.A"
        threat_id = "2147719969"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Contentocrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4a 45 6e 63 72 79 70 74 [0-32] 50 61 73 5a 69 70 [0-16] 43 6f 6e 66 69 67 [0-32] 53 61 6e 64 62 6f 78 65 73}  //weight: 1, accuracy: Low
        $x_1_2 = "ActiveXObject('Scripting.FileSystemObject');setInterval(function(){try{o.DeleteFile" ascii //weight: 1
        $x_1_3 = "!!!WALLPAPER!!!" ascii //weight: 1
        $x_2_4 = ":\\DEV\\GLOBE\\LOCKER\\uBigIntsV3.pas" ascii //weight: 2
        $x_2_5 = {2e 65 78 65 20 44 [0-16] 65 6c 65 74 [0-16] 65 20 53 68 61 [0-16] 64 6f 77 73 20 2f 41 [0-16] 6c 6c 20 2f 51 [0-16] 75 69 65 74}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

