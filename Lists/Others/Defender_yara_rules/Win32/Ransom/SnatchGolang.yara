rule Ransom_Win32_SnatchGolang_NVR_2147746191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/SnatchGolang.NVR!MTB"
        threat_id = "2147746191"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "SnatchGolang"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "README_5OAXN_DATA.txt" ascii //weight: 1
        $x_1_2 = "You may be a victim of fraud." ascii //weight: 1
        $x_1_3 = "To prove that I can recover your files, I am ready to decrypt any three files for free (except databases, Excel and backups)" ascii //weight: 1
        $x_1_4 = "/root/go/src/snatch/config.go" ascii //weight: 1
        $x_1_5 = "/root/go/src/snatch/services.go" ascii //weight: 1
        $x_1_6 = "/root/go/src/snatch/main.go" ascii //weight: 1
        $x_1_7 = "/root/go/src/snatch/loger.go" ascii //weight: 1
        $x_1_8 = "/root/go/src/snatch/files.go" ascii //weight: 1
        $x_1_9 = "/root/go/src/snatch/dirs.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

