rule Ransom_Win32_SyncCrypt_A_2147723089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/SyncCrypt.A"
        threat_id = "2147723089"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "SyncCrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "AMMOUNT.txt" ascii //weight: 1
        $x_1_2 = "move /y readme." ascii //weight: 1
        $x_1_3 = "cmd /c net view" ascii //weight: 1
        $x_1_4 = "/s /b /a-d >>" ascii //weight: 1
        $x_1_5 = "\\desktop\\readme\\" ascii //weight: 1
        $x_1_6 = "readme.png\" && exit" ascii //weight: 1
        $x_1_7 = "readme.html\" && exit" ascii //weight: 1
        $x_1_8 = "start tmp.bat" ascii //weight: 1
        $x_1_9 = "if exist \"sync.exe\" goto Repeat" ascii //weight: 1
        $x_2_10 = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAuHSaciH" ascii //weight: 2
        $x_1_11 = {2e 6b 6b 00 74 6d 70 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_12 = "\\BackupClient" ascii //weight: 1
        $x_2_13 = {c6 40 0a 00 e8 ?? ?? ?? ?? 31 d2 b9 1a 00 00 00 f7 f1 8a 82 ?? ?? ?? ?? 88 04 1e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

