rule PWS_Win32_Velara_A_2147647164_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Velara.A"
        threat_id = "2147647164"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Velara"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Valera.vbs" wide //weight: 1
        $x_1_2 = "g-pass" wide //weight: 1
        $x_1_3 = "Call SendPost(\"smtp.mail.ru\",\"ebet.arhipova@mail.ru" ascii //weight: 1
        $x_1_4 = "file of open password Mozila" ascii //weight: 1
        $x_1_5 = "If ext = \"Cookies\"Then" ascii //weight: 1
        $x_1_6 = "Flds.Item(\"http://schemas.microsoft.com/cdo/configuration/sendpassword\")=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

