rule TrojanDownloader_Win32_Gonedum_A_2147655040_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Gonedum.A"
        threat_id = "2147655040"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Gonedum"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BD96C556-65A3-11D0-983A-00C04FC29E36" ascii //weight: 1
        $x_1_2 = "set tmp = F.Buildpath(tmp,fname1)" ascii //weight: 1
        $x_1_3 = "S.savetofile fname1,2" ascii //weight: 1
        $x_1_4 = "Q.Shellexecute fname1,\"\",\"\",\"open\",0" ascii //weight: 1
        $x_1_5 = "fname1=\"g01d.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

