rule TrojanDownloader_Win32_Nymeria_RDA_2147838061_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Nymeria.RDA!MTB"
        threat_id = "2147838061"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymeria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//raw.githubusercontent.com/donpinkywu/donp/main/fiscal.wsf" ascii //weight: 1
        $x_1_2 = "RUNWAIT ( @COMSPEC & \" /c \" & \"cscript.exe \" & $SFILE & \" ALL /Q /NoCancel\" )" ascii //weight: 1
        $x_1_3 = "$SDIRECTORY = @TEMPDIR & $SFILE" ascii //weight: 1
        $x_1_4 = "$HDOWNLOAD = INETGET ( $SURL , $SDIRECTORY , 17 , 1 )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

